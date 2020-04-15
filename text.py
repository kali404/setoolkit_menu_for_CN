#!/usr/bin/env python
########################################################################
#
# text menu for set menu stuff
#
########################################################################
from src.core.setcore import bcolors, get_version, check_os, meta_path

# grab version of SET
define_version = get_version()

# check operating system
operating_system = check_os()

# grab metasploit path
msf_path = meta_path()

PORT_NOT_ZERO = "Port cannot be zero!\n端口不能为零!"
PORT_TOO_HIGH = "Let's stick with the LOWER 65,535 ports...\n端口不能超过65,535"

main_text = " Select from the menu:\n从菜单选择:\n"

main_menu = ['Social-Engineering Attacks [社会工程学攻击]',
             'Penetration Testing (Fast-Track)[渗透测试(快速)]',
             'Third Party Modules [第三方模块]',
             'Update the Social-Engineer Toolkit[更新社会工程学工具包]',
             'Update SET configuration[更新SET配置]',
             'Help, Credits, and About[帮助,和关于']

main = ['Spear-Phishing Attack Vectors[鱼叉式钓鱼网络攻击]',
        'Website Attack Vectors[WBE攻击向量]',
        'Infectious Media Generator[传染性媒体生成器]',
        'Create a Payload and Listener[创建有效载荷和侦听器]',
        'Mass Mailer Attack[群发邮件攻击]',
        'Arduino-Based Attack Vector[基于Arduino(ps:单片机?)的攻击向量]',
        'Wireless Access Point Attack Vector[无线接入点攻击向量]',
        'QRCode Generator Attack Vector[二维码生成器攻击向量]',
        'Powershell Attack Vectors[PowerShell 攻击媒介]',
        'Third Party Modules[第三方模块]']

spearphish_menu = ['Perform a Mass Email Attack[进行大规模电子邮件攻击]',
                   'Create a FileFormat Payload[创建文件格式有效荷载]',
                   'Create a Social-Engineering Template[创建社交工程模板]',
                   '0D']

spearphish_text = ("""
 The """ + bcolors.BOLD + """Spearphishing""" + bcolors.ENDC + """ module allows you to specially craft email messages and send
 them to a large (or small) number of people with attached fileformat malicious
 payloads. If you want to spoof your email address, be sure "Sendmail" is in-
 stalled (apt-get install sendmail) and change the config/set_config SENDMAIL=OFF
 flag to SENDMAIL=ON.

 There are two options, one is getting your feet wet and letting SET do
 everything for you (option 1), the second is to create your own FileFormat
 payload and use it in your own attack. Either way, good luck and enjoy!
 
他们向大量(或少量)人附加了恶意的文件格式
有效载荷。如果你想欺骗你的电子邮件地址，一定要“发送邮件”在-
停止(apt-get install sendmail)并更改config/set_config 
SENDMAIL=OFF
flag to SENDMAIL=ON.

有两种选择，一种是让你的脚湿了，让它自己干
对于您的一切(选项1)，第二个是创建您自己的文件格式
有效载荷和使用它在你自己的攻击。不管怎样，祝你好运，好好享受吧!
""")

webattack_menu = ['Java Applet Attack Method[java 小应用程序攻击方法]',
                  'Metasploit Browser Exploit Method[Metasploit 浏览器攻击方法]',
                  'Credential Harvester Attack Method[凭证收割机攻击方法]',
                  'Tabnabbing Attack Method[小圆面包攻击方法]',
                  'Web Jacking Attack Method[网页劫持攻击方法]',
                  'Multi-Attack Web Method[Multi-Attack攻击方法]',
                  'HTA Attack Method[HTA攻击方法]',
                  '0D']

fasttrack_menu = ['Microsoft SQL Bruter[Microsoft SQL 爆破]',
                  'Custom Exploits[自定义利用]',
                  'SCCM Attack Vector[SCCM 攻击向量]',
                  'Dell DRAC/Chassis Default Checker[底盘默认检查]',
                  'RID_ENUM - User Enumeration Attack[RID_ENUM用户枚举攻击]',
                  'PSEXEC Powershell Injection[PSEXEC Powershell 注入]',
                  '0D']

fasttrack_text = ("""
Welcome to the Social-Engineer Toolkit - """ + bcolors.BOLD + """Fast-Track Penetration Testing platform""" + bcolors.ENDC + """. These attack vectors
have a series of exploits and automation aspects to assist in the art of penetration testing. SET
now incorporates the attack vectors leveraged in Fast-Track. All of these attack vectors have been
completely rewritten and customized from scratch as to improve functionality and capabilities.

有一系列的利用和自动化方面，以协助艺术的渗透测试。集
现在合并在快速通道中使用的攻击向量。所有这些攻击载体都是
完全重写和自定义从零开始，以改善功能和能力。
""")

fasttrack_exploits_menu1 = ['MS08-067 (Win2000, Win2k3, WinXP)[xp系列系统]',
                            'Mozilla Firefox 3.6.16 mChannel Object Use After Free Exploit (Win7)[火狐对象使用win7]',
                            'Solarwinds Storage Manager 5.1.0 Remote SYSTEM SQL Injection Exploit[SQl5.1.0远程注入]',
                            'RDP | Use after Free - Denial of Service[RDP拒绝服务]',
                            'MySQL Authentication Bypass Exploit[MYSql认证绕过]',
                            'F5 Root Authentication Bypass Exploit[F5认证绕过漏洞]',
                            '0D']

fasttrack_exploits_text1 = ("""
Welcome to the Social-Engineer Toolkit - Fast-Track Penetration Testing """ + bcolors.BOLD + """Exploits Section""" + bcolors.ENDC + """. This
menu has obscure exploits and ones that are primarily python driven. This will continue to grow over time.
欢迎来到社会工程师工具包-快速通道渗透测试
菜单有模糊的漏洞和一些主要是python驱动的漏洞。随着时间的推移，这将继续增长。
""")

fasttrack_mssql_menu1 = ['Scan and Attack MSSQL[扫描和攻击MSSQL]',
                         'Connect directly to MSSQL[直接连接MSSQL]',
                         '0D']

fasttrack_mssql_text1 = ("""
Welcome to the Social-Engineer Toolkit - Fast-Track Penetration Testing """ + bcolors.BOLD + """Microsoft SQL Brute Forcer""" + bcolors.ENDC + """. This
attack vector will attempt to identify live MSSQL servers and brute force the weak account passwords that
may be found. If that occurs, SET will then compromise the affected system by deploying a binary to
hexadecimal attack vector which will take a raw binary, convert it to hexadecimal and use a staged approach
in deploying the hexadecimal form of the binary onto the underlying system. At this point, a trigger will occur
to convert the payload back to a binary for us.

欢迎来到社会工程师工具包-快速通道渗透测试

这攻击矢量将试图识别活MSSQL服务器和蛮力帐户密码
可能被发现。如果发生这种情况，SET将通过部署一个二进制文件来危害受影响的系统
十六进制攻击向量，它将采用一个原始二进制，转换为十六进制，并使用分阶段的方法
将二进制的十六进制形式部署到底层系统中。此时，将发生触发器
将有效载荷转换成二进制。
""")

webattack_text = ("""
The Web Attack module is a unique way of utilizing multiple web-based attacks in order to compromise the intended victim.\n\n
[Web攻击模块是一种利用多种基于Web的攻击来攻击目标的独特方式。]\n
The """ + bcolors.BOLD + """Java Applet Attack""" + bcolors.ENDC + """ method will spoof a Java Certificate and deliver a metasploit based payload. Uses a customized java applet created by Thomas Werth to deliver the payload.\n
[方法会欺骗一个Java证书，并交付一个基于metasploit的有效负载。使用由Thomas Werth创建的自定义java applet来交付负载。]\n
The """ + bcolors.BOLD + """Metasploit Browser Exploit""" + bcolors.ENDC + """ method will utilize select Metasploit browser exploits through an iframe and deliver a Metasploit payload.\n
[方法将通过iframe利用select Metasploit浏览器，并交付Metasploit有效负载。]\n
The """ + bcolors.BOLD + """Credential Harvester""" + bcolors.ENDC + """ method will utilize web cloning of a web- site that has a username and password field and harvest all the information posted to the website.\n
[方法将利用具有用户名和密码字段的网站的web克隆，并获取发布到网站的所有信息。]\n
The """ + bcolors.BOLD + """TabNabbing""" + bcolors.ENDC + """ method will wait for a user to move to a different tab, then refresh the page to something different.\n
[方法将等待用户移动到不同的选项卡，然后刷新页面到不同的地方。]\n
The """ + bcolors.BOLD + """Web-Jacking Attack""" + bcolors.ENDC + """ method was introduced by white_sheep, emgent. This method utilizes iframe replacements to make the highlighted URL link to appear legitimate however when clicked a window pops up then is replaced with the malicious link. You can edit the link replacement settings in the set_config if its too slow/fast.\n
[此方法使用iframe替换使突出显示的URL链接显示为合法，但是当单击一个窗口时弹出的链接将被恶意链接替换。如果速度太慢/太快，可以在set_config中编辑链接替换设置。]\n
The """ + bcolors.BOLD + """Multi-Attack""" + bcolors.ENDC + """ method will add a combination of attacks through the web attack menu. For example you can utilize the Java Applet, Metasploit Browser, Credential Harvester/Tabnabbing all at once to see which is successful.\n
[方法将通过web攻击菜单添加攻击组合。例如，您可以同时使用Java Applet、Metasploit浏览器、凭证收割机/Tabnabbing来查看哪个是成功的。]\n
The """ + bcolors.BOLD + """HTA Attack""" + bcolors.ENDC + """ method will allow you to clone a site and perform powershell injection through HTA files which can be used for Windows-based powershell exploitation through the browser.\n
[方法将允许您克隆一个站点，并通过HTA文件执行powershell注入，HTA文件可用于通过浏览器进行基于windows的powershell开发。]\n
""")

webattack_vectors_menu = ['Web Templates[WEB 模板]',
                          'Site Cloner[站点克隆]',
                          'Custom Import\n[自定义导入]\n',
                          ]

webattack_vectors_text = ("""
 The first method will allow SET to import a list of pre-defined web
 applications that it can utilize within the attack.

 The second method will completely clone a website of your choosing
 and allow you to utilize the attack vectors within the completely
 same web application you were attempting to clone.

 The third method allows you to import your own website, note that you
 should only have an index.html when using the import website
 functionality.
 
第一个方法允许SET导入一个预定义的web列表
它可以在攻击中利用的应用程序。

第二种方法将完全克隆你选择的网站
允许你完全利用攻击向量
您试图克隆的同一web应用程序。

第三种方法允许你导入自己的网站，注意你
当使用导入网站时应该只有index.html吗
功能。
   """)

teensy_menu = ['Powershell HTTP GET MSF Payload[Powershell HTTP获取MSF有效载荷]',
               'WSCRIPT HTTP GET MSF Payload[WSCRIPT HTTP获取MSF有效载荷]',
               'Powershell based Reverse Shell Payload[基于Powershell的反向Shell有效载荷]',
               'Internet Explorer/FireFox Beef Jack Payload[Internet Explorer/FireFox Beef Jack负载]',
               'Go to malicious java site and accept applet Payload[进入恶意java网站并接受applet有效载荷]',
               'Gnome wget Download Payload[Gnome wget下载有效载荷]',
               'Binary 2 Teensy Attack (Deploy MSF payloads)[二进制2小攻击(部署MSF有效载荷)]',
               'SDCard 2 Teensy Attack (Deploy Any EXE)[SDCard 2小攻击(部署任何EXE)]',
               'SDCard 2 Teensy Attack (Deploy on OSX)[SDCard 2小攻击(部署在OSX上)]',
               'X10 Arduino Sniffer PDE and Libraries[X10 Arduino嗅探器PDE和库]',
               'X10 Arduino Jammer PDE and Libraries[ X10 Arduino干扰器PDE和库]',
               'Powershell Direct ShellCode Teensy Attack[Powershell直接shell代码小攻击]',
               'Peensy Multi Attack Dip Switch + SDCard Attack[Peensy多重攻击Dip开关+ SDCard攻击]',
	            'HID Msbuild compile to memory Shellcode Attack[HID Msbuild编译到内存外壳代码攻击]',
               '0D']

teensy_text = ("""
 The """ + bcolors.BOLD + """Arduino-Based Attack""" + bcolors.ENDC + """ Vector utilizes the Arduin-based device to
 program the device. You can leverage the Teensy's, which have onboard
 storage and can allow for remote code execution on the physical
 system. Since the devices are registered as USB Keyboard's it
 will bypass any autorun disabled or endpoint protection on the
 system.

 You will need to purchase the Teensy USB device, it's roughly
 $22 dollars. This attack vector will auto generate the code
 needed in order to deploy the payload on the system for you.

 This attack vector will create the .pde files necessary to import
 into Arduino (the IDE used for programming the Teensy). The attack
 vectors range from Powershell based downloaders, wscript attacks,
 and other methods.

 For more information on specifications and good tutorials visit:

 http://www.irongeek.com/i.php?page=security/programmable-hid-usb-keystroke-dongle

 To purchase a Teensy, visit: http://www.pjrc.com/store/teensy.html
 Special thanks to: IronGeek, WinFang, and Garland

 This attack vector also attacks X10 based controllers, be sure to be leveraging
 X10 based communication devices in order for this to work.

 Select a payload to create the pde file to import into Arduino:
 
项目的设备。你可以利用船上的小卫星
存储并允许在物理上执行远程代码
系统。因为设备被注册为USB键盘的it
将绕过任何自动运行禁用或端点保护系统。
你需要购买一个很小的USB设备，大概是这样
22美元。这个攻击向量将自动生成代码
以便为您在系统上部署有效负载。
这个攻击向量将创建导入所需的.pde文件
进入Arduino(用于编写Teensy的IDE)。这次袭击
矢量包括基于Powershell的下载程序、wscript攻击、
和其他方法。

更多关于规范的信息和好的教程请访问:
http://www.irongeek.com/i.php?page=security/programmable-hid-usb-keystroke-dongle
要购买Teensy，请访问:http://www.pjrc.com/store/teensy.html
特别感谢:IronGeek, WinFang和Garland

此攻击向量还攻击基于X10的控制器，请务必加以利用
基于X10的通信设备，以使其工作。
选择一个有效负载来创建要导入Arduino的pde文件:
""")

wireless_attack_menu = ['Start the SET Wireless Attack Vector Access Point[启动设置的无线攻击向量接入点]',
                        'Stop the SET Wireless Attack Vector Access Point[停止设置无线攻击向量接入点]',
                        '0D']


wireless_attack_text = """
 The """ + bcolors.BOLD + """Wireless Attack""" + bcolors.ENDC + """ module will create an access point leveraging your
 wireless card and redirect all DNS queries to you. The concept is fairly
 simple, SET will create a wireless access point, dhcp server, and spoof
 DNS to redirect traffic to the attacker machine. It will then exit out
 of that menu with everything running as a child process.

 You can then launch any SET attack vector you want, for example the Java
 Applet attack and when a victim joins your access point and tries going to
 a website, will be redirected to your attacker machine.

 This attack vector requires AirBase-NG, AirMon-NG, DNSSpoof, and dhcpd3.

无线网卡和重定向所有DNS查询给你。这个概念是公平的
简单来说，SET将创建一个无线接入点、dhcp服务器和欺骗
将流量重定向到攻击者的机器。然后它将退出
所有内容都作为子进程运行。
然后，您可以启动任何您想要的集合攻击向量，例如Java
Applet攻击，当一个受害者加入你的接入点，并试图去
一个网站，将被重定向到您的攻击机器。
这种攻击载体需要AirBase-NG、AirMon-NG、DNSSpoof和dhcpd3。
"""

infectious_menu = ['File-Format Exploits',
                   'Standard Metasploit Executable',
                   '0D']


infectious_text = """
 The """ + bcolors.BOLD + bcolors.GREEN + """Infectious """ + bcolors.ENDC + """USB/CD/DVD module will create an autorun.inf file and a
 Metasploit payload. When the DVD/USB/CD is inserted, it will automatically
 run if autorun is enabled.""" + bcolors.ENDC + """
""" + bcolors.BOLD + bcolors.GREEN + bcolors.ENDC + """USB/CD/DVD模块将创建一个自动运行。inf文件和a
Metasploit负载。当DVD/USB/CD被插入，它将自动
如果自动运行是启用的。”“+ bcolors。ENDC +”“”
 Pick the attack vector you wish to use: fileformat bugs or a straight executable.
 选择您希望使用的攻击向量:文件格式错误或直接的可执行文件。
"""

# used in create_payloads.py
if operating_system != "windows":
    if msf_path != False:
        payload_menu_1 = [
            'Meterpreter Memory Injection (DEFAULT)  This will drop a meterpreter payload through powershell injection',
            'Meterpreter Multi-Memory Injection      This will drop multiple Metasploit payloads via powershell injection',
            'SE Toolkit Interactive Shell            Custom interactive reverse toolkit designed for SET',
            'SE Toolkit HTTP Reverse Shell           Purely native HTTP shell with AES encryption support',
            'RATTE HTTP Tunneling Payload            Security bypass payload that will tunnel all comms over HTTP',
            'ShellCodeExec Alphanum Shellcode        This will drop a meterpreter payload through shellcodeexec',
            'Import your own executable              Specify a path for your own executable',
            'Import your own commands.txt            Specify payloads to be sent via command line\n']

if operating_system == "windows" or msf_path == False:
    payload_menu_1 = [
        'SE Toolkit Interactive Shell    Custom interactive reverse toolkit designed for SET',
        'SE Toolkit HTTP Reverse Shell   Purely native HTTP shell with AES encryption support',
        'RATTE HTTP Tunneling Payload    Security bypass payload that will tunnel all comms over HTTP\n']

payload_menu_1_text = """
What payload do you want to generate:

  Name:                                       Description:
"""

# used in gen_payload.py
payload_menu_2 = [
    'Windows Shell Reverse_TCP               Spawn a command shell on victim and send back to attacker',
    'Windows Reverse_TCP Meterpreter         Spawn a meterpreter shell on victim and send back to attacker',
    'Windows Reverse_TCP VNC DLL             Spawn a VNC server on victim and send back to attacker',
    'Windows Shell Reverse_TCP X64           Windows X64 Command Shell, Reverse TCP Inline',
    'Windows Meterpreter Reverse_TCP X64     Connect back to the attacker (Windows x64), Meterpreter',
    'Windows Meterpreter Egress Buster       Spawn a meterpreter shell and find a port home via multiple ports',
    'Windows Meterpreter Reverse HTTPS       Tunnel communication over HTTP using SSL and use Meterpreter',
    'Windows Meterpreter Reverse DNS         Use a hostname instead of an IP address and use Reverse Meterpreter',
    'Download/Run your Own Executable        Downloads an executable and runs it\n'
]


payload_menu_2_text = """\n"""

payload_menu_3_text = ""
payload_menu_3 = [
    'Windows Reverse TCP Shell              Spawn a command shell on victim and send back to attacker',
    'Windows Meterpreter Reverse_TCP        Spawn a meterpreter shell on victim and send back to attacker',
    'Windows Reverse VNC DLL                Spawn a VNC server on victim and send back to attacker',
    'Windows Reverse TCP Shell (x64)        Windows X64 Command Shell, Reverse TCP Inline',
    'Windows Meterpreter Reverse_TCP (X64)  Connect back to the attacker (Windows x64), Meterpreter',
    'Windows Shell Bind_TCP (X64)           Execute payload and create an accepting port on remote system',
    'Windows Meterpreter Reverse HTTPS      Tunnel communication over HTTP using SSL and use Meterpreter\n']

# called from create_payload.py associated dictionary = ms_attacks
create_payloads_menu = [
    'SET Custom Written DLL Hijacking Attack Vector (RAR, ZIP)',
    'SET Custom Written Document UNC LM SMB Capture Attack',
    'MS15-100 Microsoft Windows Media Center MCL Vulnerability',
    'MS14-017 Microsoft Word RTF Object Confusion (2014-04-01)',
    'Microsoft Windows CreateSizedDIBSECTION Stack Buffer Overflow',
    'Microsoft Word RTF pFragments Stack Buffer Overflow (MS10-087)',
    'Adobe Flash Player "Button" Remote Code Execution',
    'Adobe CoolType SING Table "uniqueName" Overflow',
    'Adobe Flash Player "newfunction" Invalid Pointer Use',
    'Adobe Collab.collectEmailInfo Buffer Overflow',
    'Adobe Collab.getIcon Buffer Overflow',
    'Adobe JBIG2Decode Memory Corruption Exploit',
    'Adobe PDF Embedded EXE Social Engineering',
    'Adobe util.printf() Buffer Overflow',
    'Custom EXE to VBA (sent via RAR) (RAR required)',
    'Adobe U3D CLODProgressiveMeshDeclaration Array Overrun',
    'Adobe PDF Embedded EXE Social Engineering (NOJS)',
    'Foxit PDF Reader v4.1.1 Title Stack Buffer Overflow',
    'Apple QuickTime PICT PnSize Buffer Overflow',
    'Nuance PDF Reader v6.0 Launch Stack Buffer Overflow',
    'Adobe Reader u3D Memory Corruption Vulnerability',
    'MSCOMCTL ActiveX Buffer Overflow (ms12-027)\n']

create_payloads_text = """
 Select the file format exploit you want.
 The default is the PDF embedded EXE.\n
 选择您想要的文件格式漏洞。
默认是嵌入PDF的EXE\n
           ********** PAYLOADS **********\n"""

browser_exploits_menu = [
    'Adobe Flash Player ByteArray Use After Free (2015-07-06)',
    'Adobe Flash Player Nellymoser Audio Decoding Buffer Overflow (2015-06-23)',
    'Adobe Flash Player Drawing Fill Shader Memory Corruption (2015-05-12)',
    'MS14-012 Microsoft Internet Explorer TextRange Use-After-Free (2014-03-11)',
    'MS14-012 Microsoft Internet Explorer CMarkup Use-After-Free (2014-02-13)',
    'Internet Explorer CDisplayPointer Use-After-Free (10/13/2013)',
    'Micorosft Internet Explorer SetMouseCapture Use-After-Free (09/17/2013)',
    'Java Applet JMX Remote Code Execution (UPDATED 2013-01-19)',
    'Java Applet JMX Remote Code Execution (2013-01-10)',
    'MS13-009 Microsoft Internet Explorer SLayoutRun Use-AFter-Free (2013-02-13)',
    'Microsoft Internet Explorer CDwnBindInfo Object Use-After-Free (2012-12-27)',
    'Java 7 Applet Remote Code Execution (2012-08-26)',
    'Microsoft Internet Explorer execCommand Use-After-Free Vulnerability (2012-09-14)',
    'Java AtomicReferenceArray Type Violation Vulnerability (2012-02-14)',
    'Java Applet Field Bytecode Verifier Cache Remote Code Execution (2012-06-06)',
    'MS12-037 Internet Explorer Same ID Property Deleted Object Handling Memory Corruption (2012-06-12)',
    'Microsoft XML Core Services MSXML Uninitialized Memory Corruption (2012-06-12)',
    'Adobe Flash Player Object Type Confusion  (2012-05-04)',
    'Adobe Flash Player MP4 "cprt" Overflow (2012-02-15)',
    'MS12-004 midiOutPlayNextPolyEvent Heap Overflow (2012-01-10)',
    'Java Applet Rhino Script Engine Remote Code Execution (2011-10-18)',
    'MS11-050 IE mshtml!CObjectElement Use After Free  (2011-06-16)',
    'Adobe Flash Player 10.2.153.1 SWF Memory Corruption Vulnerability (2011-04-11)',
    'Cisco AnyConnect VPN Client ActiveX URL Property Download and Execute (2011-06-01)',
    'Internet Explorer CSS Import Use After Free (2010-11-29)',
    'Microsoft WMI Administration Tools ActiveX Buffer Overflow (2010-12-21)',
    'Internet Explorer CSS Tags Memory Corruption (2010-11-03)',
    'Sun Java Applet2ClassLoader Remote Code Execution (2011-02-15)',
    'Sun Java Runtime New Plugin docbase Buffer Overflow (2010-10-12)',
    'Microsoft Windows WebDAV Application DLL Hijacker (2010-08-18)',
    'Adobe Flash Player AVM Bytecode Verification Vulnerability (2011-03-15)',
    'Adobe Shockwave rcsL Memory Corruption Exploit (2010-10-21)',
    'Adobe CoolType SING Table "uniqueName" Stack Buffer Overflow (2010-09-07)',
    'Apple QuickTime 7.6.7 Marshaled_pUnk Code Execution (2010-08-30)',
    'Microsoft Help Center XSS and Command Execution (2010-06-09)',
    'Microsoft Internet Explorer iepeers.dll Use After Free (2010-03-09)',
    'Microsoft Internet Explorer "Aurora" Memory Corruption (2010-01-14)',
    'Microsoft Internet Explorer Tabular Data Control Exploit (2010-03-0)',
    'Microsoft Internet Explorer 7 Uninitialized Memory Corruption (2009-02-10)',
    'Microsoft Internet Explorer Style getElementsbyTagName Corruption (2009-11-20)',
    'Microsoft Internet Explorer isComponentInstalled Overflow (2006-02-24)',
    'Microsoft Internet Explorer Explorer Data Binding Corruption (2008-12-07)',
    'Microsoft Internet Explorer Unsafe Scripting Misconfiguration (2010-09-20)',
    'FireFox 3.5 escape Return Value Memory Corruption (2009-07-13)',
    'FireFox 3.6.16 mChannel use after free vulnerability (2011-05-10)',
    'Metasploit Browser Autopwn (USE AT OWN RISK!)\n']

browser_exploits_text = """
 Enter the browser exploit you would like to use [8]:
"""

# this is for the powershell attack vectors
powershell_menu = ['Powershell Alphanumeric Shellcode Injector',
                   'Powershell Reverse Shell',
                   'Powershell Bind Shell',
                   'Powershell Dump SAM Database',
                   '0D']

powershell_text = ("""
The """ + bcolors.BOLD + """Powershell Attack Vector""" + bcolors.ENDC + """ module allows you to create PowerShell specific attacks. These attacks will allow you to use PowerShell which is available by default in all operating systems Windows Vista and above. PowerShell provides a fruitful  landscape for deploying payloads and performing functions that  do not get triggered by preventative technologies.[模块允许您创建PowerShell特定的攻击。这些攻击将允许您使用PowerShell, PowerShell在所有Windows Vista及以上操作系统中都是默认可用的。PowerShell为部署有效负载和执行预防性技术无法触发的功能提供了一个富有成效的前景。]\n""")


encoder_menu = ['shikata_ga_nai',
                'No Encoding',
                'Multi-Encoder',
                'Backdoored Executable\n']

encoder_text = """
Select one of the below, 'backdoored executable' is typically the best. However,
most still get picked up by AV. You may need to do additional packing/crypting
in order to get around basic AV detection.[选择下面其中一个，‘backdoored可执行文件’通常是最好的。然而,
大多数仍然会被AV选中。你可能需要做额外的包装/加密
以绕过基本的反病毒检测。]
"""

dll_hijacker_text = """
 The DLL Hijacker vulnerability will allow normal file extenstions to
 call local (or remote) .dll files that can then call your payload or
 executable. In this scenario it will compact the attack in a zip file
 and when the user opens the file extension, will trigger the dll then
 ultimately our payload. During the time of this release, all of these
 file extensions were tested and appear to work and are not patched. This
 will continiously be updated as time goes on.[DLL Hijacker漏洞将允许正常的文件扩展到
调用本地(或远程).dll文件，然后可以调用您的有效负载或
可执行文件。在这种情况下，它会将攻击压缩到zip文件中
而当用户打开文件扩展名时，则会触发dll
最终我们的有效载荷。在这个版本中，所有这些
文件扩展名已经过测试，似乎工作，没有补丁。这
将随着时间的推移不断更新。]
"""

fakeap_dhcp_menu = ['10.0.0.100-254',
                    '192.168.10.100-254\n']

fakeap_dhcp_text = "Please choose which DHCP Config you would like to use[请选择你想使用的DHCP配置:]: "
