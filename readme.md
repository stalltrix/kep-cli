# kepcli

### 使用方法 : 

1.生成完全证书(包括 mainkey,pkey,sig)

```bash
kepcli gen
```

<br>

2.获取key的dns基础txt记录

```bash
kepcli dnstxt
```

此dns记录为mainkey的base32以及pkey的des，也可手动两步获取

```bash
kepcli base32
kepcli des
```

<br>

3.以主密钥mainkey获取新的pkey(子密钥)

```bash
kepcli newkey -pkey mykey
```

-pkey可选参数

<br>

4.发送msg

```bash
kepcli send -addr [http://web] -auth [token]
```

<br>

5.初始化索引

```bash
kepcli init
```

<br>

6.检查索引是否损坏

```bash
kepcli chk
```

<br>

---

在v0.1.7以前，需要添加`cli -act cmd`的flags显示指定，高于此版本可直接在末尾输入命令`cli cmd`

<br>

---

### 其他事项

如果使用send，那么-addr [http://web] -auth [token]是必须的

不过建议新手send操作直接使用网页端发送，更加方便，同时不容易出错