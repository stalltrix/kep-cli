# kepcli

### 使用方法 : 

1.生成完全证书(包括 mainkey,pkey,sig)

```bash
kepcli -act gen
```

<br>

2.获取mainkey的base32

```bash
kepcli -act base32
```

<br>

3.以主mainkey获取新的pkey(子密钥)

```bash
kepcli -act newkey -pkey mykey
```

-pkey可选参数

<br>

4.发送msg

```bash
kepcli -act send -addr [http://web] -auth [token]
```

如果使用send，那么-addr [http://web] -auth [token]是必须的

不过建议新手send操作直接使用网页端发送，更加方便，同时不容易出错