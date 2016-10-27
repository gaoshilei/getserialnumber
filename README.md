##  前言  
在iOS7之前我们可以通过`- (NSString *)uniqueIdentifier`这个方法获取iPhone的唯一标识符，也叫作UDID。不过自从iOS7苹果就把这个方法给禁了，此时我们想要获取iPhone的唯一标识符就很困难。  
不过苹果提供一个叫做IDFA的标识符，这个IDFA是广告标识符用来追踪广告投放的，不过用户可以在设置中手动重置IDFA，可靠性很低，目前常见的两种标记iPhone的方式为  
*  openUDID  
*  IDFA或UUID+keychain  

这两种模式都有个弊端，用户重置手机或者刷机唯一标识符会发生变化，不过对于大多数情况是够用了。看来苹果是把路给封死了，有没有办法拿到之前的UDID呢？我们注意到iPhone的设置通用关于里面有手机的硬件信息，其中有一个serialNumber，这个serialnumber就是我们查询手机是否过保的依据，那么它肯定是唯一的，所以下文是围绕这个进行的探索。最终是可以拿到这个serialNumber的， 不过由于苹果的沙盒限制，所以只能在越狱机中拿到，如果想在非越狱机中拿到必须添加entitlements文件来获取权限，可想而知这个应用是无法上架的。**下文仅作为逆向工程的一种思路和探索，请勿用于非法用途。**  

##  正文
###	一、SSH连接手机（USB模式）
####	1.映射端口
```
LeonLei-MBP:~ gaoshilei$ /Users/gaoshilei/Desktop/reverse/USBSSH/tcprelay.py -t 22:6666
Forwarding local port 6666 to remote port 22
```
####	2.连接手机，并且用grep命令快速筛选当前我们要调试的应用Preferences，附加debugserver开始1234端口等待lldb调试
```
LeonLei-MBP:~ gaoshilei$ ssh root@localhost -p 6666
iPhone-5S:~ root# ps -e | grep Pre
270 ??         0:00.29 /System/Library/PrivateFrameworks/MobileSoftwareUpdate.framework/XPCServices/com.apple.MobileSoftwareUpdate.CleanupPreparePathService.xpc/com.apple.MobileSoftwareUpdate.CleanupPreparePathService
1192 ??         0:14.26 /var/db/stash/_.fP74Fg/Applications/Preferences.app/Preferences
1289 ttys000    0:00.01 grep Pre
iPhone-5S:~ root# debugserver *:1234 -a "Preferences"
debugserver-@(#)PROGRAM:debugserver  PROJECT:debugserver-340.3.51.1
for arm64.
Attaching to process Preferences...
Listening to port 1234 for a connection from *...
```
####	3.完成以上两步接下来就可以进行lldb调试了，首先要把远端（手机）的1234端口映射到本地，跟前面提到的SSH端口映射一样
```
LeonLei-MBP:~ gaoshilei$ /Users/gaoshilei/Desktop/reverse/USBSSH/tcprelay.py -t 1234:1234
Forwarding local port 1234 to remote port 1234
```
###	二、通过LLDB、IDA寻找线索
lldb的调试端口已经打开，此时我们可以进入调试

```
LeonLei-MBP:~ gaoshilei$ lldb
(lldb) process connect connect://localhost:1234
Process 1192 stopped  
* thread #1: tid = 0x523a6, 0x000000019a3c8a40 libsystem_kernel.dylib`mach_msg_trap + 8, queue = 'com.apple.main-thread', stop reason = signal SIGSTOP  
frame #0: 0x000000019a3c8a40 libsystem_kernel.dylib`mach_msg_trap + 8
libsystem_kernel.dylib`mach_msg_trap:
->  0x19a3c8a40 <+8>: ret    
libsystem_kernel.dylib`mach_msg_overwrite_trap:
0x19a3c8a44 <+0>: movn   x16, #0x1f
0x19a3c8a48 <+4>: svc    #0x80
0x19a3c8a4c <+8>: ret    
```
此时我们已经成功进入Preferences的调试阶段，先c一下，让程序继续运行

```
(lldb) c
Process 1192 resuming
```
这么做的原因是我们待会要打印image的基地址偏移，有可能在我们打印的image list中没有我们想要的image。
此时我们已经找到到Preference.framework的基地址偏移，见下图

```
(lldb) im li -o -f
[  0] 0x00000000000dc000 /var/db/stash/_.fP74Fg/Applications/Preferences.app/Preferences(0x00000001000dc000)
[  1] 0x0000000100100000 /Library/MobileSubstrate/MobileSubstrate.dylib(0x0000000100100000)
[  2] 0x0000000002e50000 /Users/gaoshilei/Library/Developer/Xcode/iOS DeviceSupport/9.1 (13B143)/Symbols/System/Library/PrivateFrameworks/BulletinBoard.framework/BulletinBoard
[  3] 0x0000000002e50000 /Users/gaoshilei/Library/Developer/Xcode/iOS DeviceSupport/9.1 (13B143)/Symbols/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
[  4] 0x0000000002e50000 /Users/gaoshilei/Library/Developer/Xcode/iOS DeviceSupport/9.1 (13B143)/Symbols/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit
…
[ 44] 0x0000000002e50000 /Users/gaoshilei/Library/Developer/Xcode/iOS DeviceSupport/9.1 (13B143)/Symbols/System/Library/PrivateFrameworks/Preferences.framework/Preferences
…  
```
我们要找的image的序号在这里是44，它的基地址偏移为0x2e50000，我们把从iPhone中导出的PrivateFrameworks中的Preferences.framework丢到IDA中进行分析，这个二进制文件比较小，很快就分析完成，在前面我们已经知道iPhone的唯一序列号serial number是通过PSListController生成的，并且我们知道这是一个cell，我们要去调试`[PSListController tableView:cellForRowAtIndexPath:]`这个方法，从中找到cell值的来源，从而找到获取序列号的方法。

```
__text:00000001908040C8 ; -[PSListController tableView:cellForRowAtIndexPath:]
__text:00000001908040C8 __PSListController_tableView_cellForRowAtIndexPath__
__text:00000001908040C8                                         ; DATA XREF: __objc_const:000000019C069B88o
__text:00000001908040C8
__text:00000001908040C8 var_80          = -0x80
__text:00000001908040C8 var_78          = -0x78
__text:00000001908040C8 var_70          = -0x70
__text:00000001908040C8 var_68          = -0x68
__text:00000001908040C8 var_60          = -0x60
__text:00000001908040C8 var_50          = -0x50
__text:00000001908040C8 var_40          = -0x40
__text:00000001908040C8 var_30          = -0x30
__text:00000001908040C8 var_20          = -0x20
__text:00000001908040C8 var_10          = -0x10
__text:00000001908040C8
__text:00000001908040C8                 STP             X28, X27, [SP,#var_60]!
__text:00000001908040CC                 STP             X26, X25, [SP,#0x60+var_50]
__text:00000001908040D0                 STP             X24, X23, [SP,#0x60+var_40]
__text:00000001908040D4                 STP             X22, X21, [SP,#0x60+var_30]
__text:00000001908040D8                 STP             X20, X19, [SP,#0x60+var_20]
__text:00000001908040DC                 STP             X29, X30, [SP,#0x60+var_10]
__text:00000001908040E0                 ADD             X29, SP, #0x60+var_10
__text:00000001908040E4                 SUB             SP, SP, #0x20
__text:00000001908040E8                 MOV             X21, X3
__text:00000001908040EC                 MOV             X20, X0
__text:00000001908040F0                 MOV             X0, X2
__text:00000001908040F4                 BL              0x96C400A0
__text:00000001908040F8                 MOV             X26, X0
__text:00000001908040FC                 ADRP            X8, #off_19DACC568@PAGE
__text:0000000190804100                 LDR             X1, [X8,#off_19DACC568@PAGEOFF]
__text:0000000190804104                 MOV             X0, X20
__text:0000000190804108                 MOV             X2, X21
__text:000000019080410C                 BL              0x96C39BC0
__text:0000000190804110                 MOV             X2, X0
__text:0000000190804114                 ADRP            X8, #_OBJC_IVAR_$_PSListController._specifiers@PAGE ; NSArray *_specifiers;
__text:0000000190804118                 LDRSW           X27, [X8,#_OBJC_IVAR_$_PSListController._specifiers@PAGEOFF] ; NSArray *_specifiers;
__text:000000019080411C                 LDR             X0, [X20,X27]
__text:0000000190804120                 ADRP            X8, #off_19DACC558@PAGE
……
```
我们在Preference.framework中基地址为0x190804114的位置打个断点，具体的做法是：

```
(lldb) br s -a 0x190804114+0x2e50000
Breakpoint 1: where = Preferences`-[PSListController tableView:cellForRowAtIndexPath:] + 76, address = 0x0000000193654114
Process 1192 stopped
* thread #1: tid = 0x523a6, 0x0000000193654114 Preferences`-[PSListController tableView:cellForRowAtIndexPath:] + 76, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000193654114 Preferences`-[PSListController tableView:cellForRowAtIndexPath:] + 76
Preferences`-[PSListController tableView:cellForRowAtIndexPath:]:
->  0x193654114 <+76>: adrp   x8, 53965
0x193654118 <+80>: ldrsw  x27, [x8, #516]
0x19365411c <+84>: ldr    x0, [x20, x27]
0x193654120 <+88>: adrp   x8, 53960
```
这里断点这样打是因为系统加载可执行文件和各种framework的时候会有一个地址偏移，我们在打断点的时候要把这个偏移量加上，这样我们打的断点才是准确的。
可以看到我们已经成功打了一个断点，断点的address = 0x193654114。此时我们打印变量x0和x27的值

```
(lldb) po $x0
13
(lldb) po $x27
1104
```
我们执行ni让程序继续（这里的`ni`命令相当于Xcode的那个下箭头命令，也就是下一行）

```
(lldb) ni
Process 1192 stopped
* thread #1: tid = 0x523a6, 0x0000000193654118 Preferences`-[PSListController tableView:cellForRowAtIndexPath:] + 80, queue = 'com.apple.main-thread', stop reason = instruction step over
frame #0: 0x0000000193654118 Preferences`-[PSListController tableView:cellForRowAtIndexPath:] + 80
Preferences`-[PSListController tableView:cellForRowAtIndexPath:]:
->  0x193654118 <+80>: ldrsw  x27, [x8, #516]
0x19365411c <+84>: ldr    x0, [x20, x27]
0x193654120 <+88>: adrp   x8, 53960
0x193654124 <+92>: ldr    x22, [x8, #1368]
(lldb) ni
Process 1192 stopped
* thread #1: tid = 0x523a6, 0x000000019365411c Preferences`-[PSListController tableView:cellForRowAtIndexPath:] + 84, queue = 'com.apple.main-thread', stop reason = instruction step over
frame #0: 0x000000019365411c Preferences`-[PSListController tableView:cellForRowAtIndexPath:] + 84
Preferences`-[PSListController tableView:cellForRowAtIndexPath:]:
->  0x19365411c <+84>: ldr    x0, [x20, x27]
0x193654120 <+88>: adrp   x8, 53960
0x193654124 <+92>: ldr    x22, [x8, #1368]
0x193654128 <+96>: mov    x1, x22
(lldb) po $x27
848

(lldb) po $x0
13
```
我们ni的两次，程序已经走到0x19080411C的位置，然后我们继续打印变量x0和x27的值

```
(lldb) po $x0
13
(lldb) po $x27
1104
```
打印出来的x0和x27都是随机数，还是没有什么收获，我们继续

```
(lldb) ni
Process 1192 stopped
* thread #1: tid = 0x523a6, 0x0000000193654120 Preferences`-[PSListController tableView:cellForRowAtIndexPath:] + 88, queue = 'com.apple.main-thread', stop reason = instruction step over
frame #0: 0x0000000193654120 Preferences`-[PSListController tableView:cellForRowAtIndexPath:] + 88
Preferences`-[PSListController tableView:cellForRowAtIndexPath:]:
->  0x193654120 <+88>:  adrp   x8, 53960
0x193654124 <+92>:  ldr    x22, [x8, #1368]
0x193654128 <+96>:  mov    x1, x22
0x19365412c <+100>: bl     0x199a89bc0               ; objc_msgSend
(lldb) po $x0
<__NSArrayI 0x13105a780>(
G: <PSSpecifier 0x12ff50cf0: ID 0, Name '' target <(null): 0x0>> 0x12ff50cf0,
<PSSpecifier 0x12ff50f50: ID NAME_CELL_ID, Name 'Name' target <AboutDataSource: 0x131028390>>,
G: <PSSpecifier 0x12ff51680: ID 2, Name '' target <(null): 0x0>> 0x12ff51680,
<PSSpecifier 0x12ff52360: ID NETWORK, Name 'Network' target <AboutDataSource: 0x131028390>>,
<PSSpecifier 0x12ff52420: ID SONGS, Name 'Songs' target <AboutDataSource: 0x131028390>>,
<PSSpecifier 0x12ff519f0: ID VIDEOS, Name 'Videos' target <AboutDataSource: 0x131028390>>,
<PSSpecifier 0x12ff51ab0: ID PHOTOS, Name 'Photos' target <AboutDataSource: 0x131028390>>,
<PSSpecifier 0x12ff51b70: ID APPLICATIONS, Name 'Applications' target <AboutDataSource: 0x131028390>>,
<PSSpecifier 0x12ff524e0: ID User Data Capacity, Name 'Capacity' target <AboutDataSource: 0x131028390>>,
<PSSpecifier 0x12ff525a0: ID User Data Available, Name 'Available' target <AboutDataSource: 0x131028390>>,
<PSSpecifier 0x12ff526a0: ID ProductVersion, Name 'Version' target <AboutDataSource: 0x131028390>>,
<PSSpecifier 0x12ff52850: ID CARRIER_VERSION, Name 'Carrier' target <AboutDataSource: 0x131028390>>,
<PSSpecifier 0x12ff52980: ID ProductModel, Name 'Model' target <AboutDataSource: 0x131028390>>,
<PSSpecifier 0x12ff52a60: ID SerialNumber, Name 'Serial Number' target <AboutDataSource: 0x131028390>>,
<PSSpecifier 0x12ff52b90: ID MACAddress, Name 'Wi-Fi Address' target <AboutDataSource: 0x131028390>>,
<PSSpecifier 0x12ff51050: ID BTMACAddress, Name 'Bluetooth' target <AboutDataSource: 0x131028390>>,
<PSSpecifier 0x12fde95d0: ID ModemVersion, Name 'Modem Firmware' target <AboutDataSource: 0x131028390>>,
G: <PSSpecifier 0x131031e90: ID 17, Name '' target <(null): 0x0>> 0x131031e90,
<PSSpecifier 0x12fde9c40: ID LEGAL_AND_REGULATORY, Name 'Legal' target <(null): 0x0>>,
G: <PSSpecifier 0x131029dc0: ID TRUST_STORE_GROUP, Name '' target <(null): 0x0>> 0x131029dc0,
<PSSpecifier 0x131033520: ID TRUST_STORE, Name 'Trust Store' target <AboutDataSource: 0x131028390>>
)
```
我们让程序执行下一步，发现此时x0已经有值了，可以明显的看出，x0的值是在0x190804114~0x19080411C这段代码生成的，下面我们的工作重点就是寻找这段代码干了什么，胜利就在眼前！下面我们验证一下这里面到底有没有我们要的序列号：

```
(lldb) po [[$x0 objectAtIndex:13] class]
PSSpecifier
(lldb) po [[$x0 objectAtIndex:13] properties]
{
cellObject = "<PSTableCell: 0x130800000; baseClass = UITableViewCell; frame = (0 565; 320 45); text = 'Serial Number'; hidden = YES; autoresize = W; tag = 4; gestureRecognizers = <NSArray: 0x12ff821c0>; layer = <CALayer: 0x12fd7d340>>";
id = SerialNumber;
isCopyable = 1;
value = DNPMVG0EFF9V;
}
```
我们打印数组中存放cell数据的object属于哪个类，发现是`PSSpecifier`，我们找到之前导出的类的头文件，发现这个类有一个叫做`properties`的实例方法，我们调用一下发现我们要的序列号就在里面`value = DNPMVG0EFF9V`，这跟iPhone设置中看到的序列号是一致的。猜测这个数组里面存放着系统设置中`PSUIAboutController`中所有cel的数据，这个数组下一个肯定要传递到cell生成的方法中，这个就不做验证了，大事重要，我们继续找序列号的生成方法。
这个`PSSpecifier`中有一个`AboutDataSource`对象，这个非常可疑，从名称上可以判断，这个类是专门用于数据处理的，不过在这之前我们还是先验证一下，在0x190804114~0x19080411C这段地址中，执行了`_PSListController._specifiers`，我们从`PSListController`的头文件（下文有讲怎么获取）中可以看到有一个specifiers属性，我们在IDA分析的文件中找到`[PSListController specifiers]`，我们先定位到方法在二进制文件中的位置：

```
__text:00000001907FE4A8 ; -[PSListController specifiers]
__text:00000001907FE4A8 __PSListController_specifiers_          ; DATA XREF: __objc_const:000000019C069A08o
__text:00000001907FE4A8
__text:00000001907FE4A8 var_40          = -0x40
__text:00000001907FE4A8 var_30          = -0x30
__text:00000001907FE4A8 var_20          = -0x20
__text:00000001907FE4A8 var_10          = -0x10
__text:00000001907FE4A8
__text:00000001907FE4A8                 STP             X24, X23, [SP,#var_40]!
__text:00000001907FE4AC                 STP             X22, X21, [SP,#0x40+var_30]
__text:00000001907FE4B0                 STP             X20, X19, [SP,#0x40+var_20]
__text:00000001907FE4B4                 STP             X29, X30, [SP,#0x40+var_10]
__text:00000001907FE4B8                 ADD             X29, SP, #0x40+var_10
__text:00000001907FE4BC                 MOV             X19, X0
__text:00000001907FE4C0                 ADRP            X8, #_OBJC_IVAR_$_PSListController._specifiers@PAGE ; NSArray *_specifiers;
__text:00000001907FE4C4                 LDRSW           X22, [X8,#_OBJC_IVAR_$_PSListController._specifiers@PAGEOFF] ; NSArray *_specifiers;
__text:00000001907FE4C8                 LDR             X8, [X19,X22]
__text:00000001907FE4CC                 CBNZ            X8, loc_1907FE5E0
__text:00000001907FE4D0                 ADRP            X8, #_OBJC_IVAR_$_PSListController._dataSource@PAGE ; id <PSSpecifierDataSource> _dataSource;
__text:00000001907FE4D4                 LDRSW           X8, [X8,#_OBJC_IVAR_$_PSListController._dataSource@PAGEOFF] ; id <PSSpecifierDataSource> _dataSource;
__text:00000001907FE4D8                 LDR             X9, [X19,X8]
__text:00000001907FE4DC                 CBZ             X9, loc_1907FE550
__text:00000001907FE4E0                 ADRP            X9, #_OBJC_IVAR_$_PSListController._requestingSpecifiersFromDataSource@PAGE ; bool _requestingSpecifiersFromDataSource;
__text:00000001907FE4E4                 LDRSW           X23, [X9,#_OBJC_IVAR_$_PSListController._requestingSpecifiersFromDataSource@PAGEOFF] ; bool _requestingSpecifiersFromDataSource;
__text:00000001907FE4E8                 MOV             W9, #1
__text:00000001907FE4EC                 STRB            W9, [X19,X23]
__text:00000001907FE4F0                 LDR             X20, [X19,X8]
__text:00000001907FE4F4                 ADRP            X8, #selRef_specifier@PAGE
__text:00000001907FE4F8                 LDR             X1, [X8,#selRef_specifier@PAGEOFF]
__text:00000001907FE4FC                 MOV             X0, X19
__text:00000001907FE500                 BL              0x96C39BC0
__text:00000001907FE504                 MOV             X29, X29
__text:00000001907FE508                 BL              0x96C41EF0
__text:00000001907FE50C                 MOV             X21, X0
__text:00000001907FE510                 ADRP            X8, #selRef_specifiersForSpecifier_observer_@PAGE
__text:00000001907FE514                 LDR             X1, 
……
```
然后在这里面下个断点看看会发生什么

```
(lldb) br s -a 0x1907FE4D0+0x198e58640
Breakpoint 9: where = Preferences`-[PSListController specifiers] + 40, address = 0x000000019364e4d0
```
我们从设置中进入通用>关于，发现一开始就走到了这个断点，我们猜测，一进入关于页面，系统会首先把所有cell的数据都准备好，然后加载UI

```
Process 1192 stopped
* thread #1: tid = 0x523a6, 0x000000019364e4d0 Preferences`-[PSListController specifiers] + 40, queue = 'com.apple.main-thread', stop reason = breakpoint 9.1
frame #0: 0x000000019364e4d0 Preferences`-[PSListController specifiers] + 40
Preferences`-[PSListController specifiers]:
->  0x19364e4d0 <+40>: adrp   x8, 53971
0x19364e4d4 <+44>: ldrsw  x8, [x8, #536]
0x19364e4d8 <+48>: ldr    x9, [x19, x8]
0x19364e4dc <+52>: cbz    x9, 0x19364e550           ; <+168>
```
我们打印变量x8和x9的值，看一下系统做了什么

```
(lldb) po $x8
<nil>
(lldb) po $x9
PSUIAboutController
```
并没有数据之类的东西值得我们关注，让断点继续往下走，走到0x19364e4dc的位置，我们再次打印变量x8和x9的值

```
(lldb) n
Process 1192 stopped
* thread #1: tid = 0x523a6, 0x000000019364e4dc Preferences`-[PSListController specifiers] + 52, queue = 'com.apple.main-thread', stop reason = instruction step over
frame #0: 0x000000019364e4dc Preferences`-[PSListController specifiers] + 52
Preferences`-[PSListController specifiers]:
->  0x19364e4dc <+52>: cbz    x9, 0x19364e550           ; <+168>
0x19364e4e0 <+56>: adrp   x9, 53971
0x19364e4e4 <+60>: ldrsw  x23, [x9, #540]
0x19364e4e8 <+64>: orr    w9, wzr, #0x1
(lldb) po $x8
952
(lldb) po $x9
<AboutDataSource: 0x131130730>
```
此时的变量x9已经变成了`AboutDataSource`，这里验证了我们上一步的猜想，所以我们重点来研究它，我们先找到这个类在哪个framework中，这里使用的是grep命令

```
LeonLei-MBP:~ gaoshilei$ grep AboutDataSource -r /Users/gaoshilei/Desktop/reverse/iOS-Runtime-Headers-9.1 
/Users/gaoshilei/Desktop/reverse/iOS-Runtime-Headers-9.1/PrivateFrameworks/PreferencesUI.framework/AboutDataSource.h:@interface AboutDataSource : PSSpecifierDataSource {
```
这里要说明一下iOS-Runtime-Headers-9.1这个文件夹是iOS9.1系统的所有头文件（共有+私有），这个你可以自己导（iOS9之后只能用runtime导，class-dump已经不行了），你也可以拿现成的用，github上面已经有雷锋把所有系统的头文件都导出来了，直接下载就可以了。我们发现`AboutDataSource`这个类在`PrivateFrameworks/PreferencesUI.framework`中，先看一下这个类里面有什么方法和属性，有一个方法`- (void)_loadValues;` 我们对它进行分析。这里又要借助IDA分析，把PreferencesUI这个二进制文件丢到IDA里面，在0x19091EBB8这个位置打个断点

```
(lldb) br s -a 0x19091EBB8+0x2e50000
Breakpoint 3: where = PreferencesUI`-[AboutDataSource _loadValues] + 1956, address = 0x000000019376ebb8
```
接下来我们进入关于来触发断点

```
(lldb) po (char *) $x28
"_setValue:forSpecifierWithKey:"
```
在这里打印变量x28的值，发现它是一个方法名，从名称来看是给`specifier`赋值的，看来我们要寻找的真相已经很近了，让代码走到下面的位置0x19376ebd8

```
Process 2107 stopped
* thread #1: tid = 0xe8e23, 0x000000019376ebd8 PreferencesUI`-[AboutDataSource _loadValues] + 1988, queue = 'com.apple.main-thread', stop reason = instruction step over
frame #0: 0x000000019376ebd8 PreferencesUI`-[AboutDataSource _loadValues] + 1988
PreferencesUI`-[AboutDataSource _loadValues]:
->  0x19376ebd8 <+1988>: bl     0x198e58640               ; MGCopyAnswer
0x19376ebdc <+1992>: mov    x22, x0
0x19376ebe0 <+1996>: mov    x1, x19
0x19376ebe4 <+2000>: bl     0x199a89bc0               ; objc_msgSend
(lldb) po $x0
SerialNumber
```
此时我们打印的x0是一个`NSCFConstantString`，本质就是一个`NSString`，继续`ni`让程序运行到0x19376ebdc

```
Process 2107 stopped
* thread #1: tid = 0xe8e23, 0x000000019376ebdc PreferencesUI`-[AboutDataSource _loadValues] + 1992, queue = 'com.apple.main-thread', stop reason = instruction step over
frame #0: 0x000000019376ebdc PreferencesUI`-[AboutDataSource _loadValues] + 1992
PreferencesUI`-[AboutDataSource _loadValues]:
->  0x19376ebdc <+1992>: mov    x22, x0
0x19376ebe0 <+1996>: mov    x1, x19
0x19376ebe4 <+2000>: bl     0x199a89bc0               ; objc_msgSend
0x19376ebe8 <+2004>: cbnz   x0, 0x19376ec4c           ; <+2104>
(lldb) po $x0
DNPMVG0EFF9V
```
在这里我们打印了变量x0的值为**DNPMVG0EFF9V**，这就是我们苦苦寻找的序列号。不难看出，序列号就是在0x19376ebd8这行拿到的，范围越来越小，敌人无路可逃！下面我们就要对这行进行分析，我们按照之前的步骤，再次走到0x19376ebd8这个位置，这不过这次我们不要`step-over`，我们用`si`跳入看看

```
(lldb) si
Process 2107 stopped
* thread #1: tid = 0xe8e23, 0x0000000198e58640 libMobileGestalt.dylib`MGCopyAnswer, queue = 'com.apple.main-thread', stop reason = instruction step into
frame #0: 0x0000000198e58640 libMobileGestalt.dylib`MGCopyAnswer
libMobileGestalt.dylib`MGCopyAnswer:
->  0x198e58640 <+0>: movz   x1, #0
0x198e58644 <+4>: b      0x198e58648               ; ___lldb_unnamed_symbol64$$libMobileGestalt.dylib

libMobileGestalt.dylib`___lldb_unnamed_symbol64$$libMobileGestalt.dylib:
0x198e58648 <+0>: stp    x24, x23, [sp, #-64]!
0x198e5864c <+4>: stp    x22, x21, [sp, #16]
此时跳入了一个静态库libMobileGestalt.dylib，我们可以在usr/lib/ibMobileGestalt.dylib找到它，我们将它扔进IDA，用当前的addr减去libMobileGestalt.dylib的基地址偏移得到它的静态地址0x196008640，对应的是一个函数MGCopyAnswer
__text:0000000196008640
__text:0000000196008640 ; =============== S U B R O U T I N E =======================================
__text:0000000196008640
__text:0000000196008640
__text:0000000196008640                 EXPORT _MGCopyAnswer
__text:0000000196008640 _MGCopyAnswer                           ; CODE XREF: sub_196005958+30p
__text:0000000196008640                                         ; sub_196006258+28p ...
__text:0000000196008640                 MOV             X1, #0
__text:0000000196008644                 B               sub_196008648
__text:0000000196008644 ; End of function _MGCopyAnswer
```
这个函数最外层只有两行代码，将立即数0赋给x1，然后跳进了子程序sub_196008648，跳进去之后进行了一些很复杂的运算，这里就不做介绍了，里面的实现大概是这样的：
x0是作为一个参数传入的，并且这里x0的值为`SerialNumber`，在地址为0x196008678的地方，这个函数中x1变成了一串随机数，有点像MD5加密之后的东西，应该是“钥匙”

```
(lldb) po (char*) $x1
"l92SaBpqIvQs+KBljuwGA"
```
在0x196008690这里，我们`setp-into`这个函数，在函数的末尾返回值的地方0x196007474打个断点，打印返回值x0

```
(lldb) po $x0
DNPMVG0EFF9V
```
这里的x0由`SerialNumber`变成了真正的序列号，并且就是在0x196008690对应的子程序sub_19600738C里面拿到的，所以我们就这样一个猜测，在`MGCopyAnswer`函数中，x0作为一个参数传入，并且在内部进行了一系列复杂的运算，拿到了获取序列号的“钥匙”x1，然后在sub_19600738C中拿到了最终的序列号。这里笔者也没有对序列号的拿到在进行进一步的深究，这里苹果做了很大的限制，再继续研究恐怕也是收获不大，而且我们在这里已经能拿到序列号了。  
###	三、验证结果  
接下来就是验证的过程了，我们写一个tweak来验证，当然也可以用其他方式来验证：
tweak的创建这里就不赘述了，我把我的tweak和makefile文件内容贴一下：
> tweak文件：

```
tweak.xm:
extern "C" NSString *MGCopyAnswer(NSString*);
%hook SpringBoard
- (void)applicationDidFinishLaunching:(id)application {
%orig;
NSString *serialNumber = [NSString stringWithFormat:@"%@",[MGCopyAnswer(@"SerialNumber") autorelease]];
UIAlertView *alert = [[UIAlertView alloc] initWithTitle:serialNumber message:nil delegate:self cancelButtonTitle:@"OK" otherButtonTitles:nil];
[alert show];
}
%end
```
这里注入系统的SpringBoard，在SB启动的时候hook住applicationDidFinishLaunching：函数，并且在这个函数里面添加获取序列号的代码，并且以弹框的形式展现出来。  
> makefile文件:

```
THEOS_DEVICE_IP = 192.168.0.115
include $(THEOS)/makefiles/common.mk
TWEAK_NAME = SerialNumber
SerialNumber_FILES = Tweak.xm
include $(THEOS_MAKE_PATH)/tweak.mk
SerialNumber_LDFLAGS = -lMobileGestalt
after-install::
install.exec "killall -9 SpringBoard"
```
其中有一行`SerialNumber_LDFLAGS = -lMobileGestalt`千万要注意，使用的时候要加载这个静态库，因为SpringBoard加载的时候我也不确定是否有加载这个库，然后我们验证一下吧！
![序列号验证-获取](http://upload-images.jianshu.io/upload_images/1787336-de4c49a4ffd6bd91.jpg?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)![序列号验证-系统](http://upload-images.jianshu.io/upload_images/1787336-78e60f103a70c27e.jpg?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)  

[此文参考了《iOS逆向工程（第二版）》](https://www.amazon.cn/iOS应用逆向工程-沙梓社/dp/B00VFDVY7E/ref=sr_1_1?ie=UTF8&qid=1477453672&sr=8-1&keywords=iOS逆向工程)
