package main

import (
    "bytes"
    "crypto/ed25519"
    "crypto/sha256"
    "encoding/binary"
	"encoding/hex"
    "fmt"
    "os"
    "time"
	"bufio"
	"strings"
	"github.com/stalltrix/kep-demo/send"
	"flag"
	"github.com/stalltrix/kep-cli/keygen"
	"encoding/base32"
	"hash/fnv"
	"net/url"
	"net/http"
	"io"
	"path/filepath"
	"github.com/stalltrix/kep-demo/kepdb"
	"github.com/stalltrix/kep-demo/kepresolv"
)

func unix40() []byte {
    var b [5]byte
    t := uint64(time.Now().Unix())
    b[0] = byte(t >> 32)
    b[1] = byte(t >> 24)
    b[2] = byte(t >> 16)
    b[3] = byte(t >> 8)
    b[4] = byte(t)
    return b[:]
}

func mustWrite(name string, data []byte) error {
    return os.WriteFile(name, data, 0600);
}

func main() {
	act := flag.String("act", "", "tool action [send/gen/base32/newkey/des/api/chk/read]")
    nextAddr := flag.String("addr", "http://127.0.0.1:8888", "send msg/api addr")
	nextAuth := flag.String("auth", "12345678", "send msg/api auth")
	pkeyN := flag.String("pkey", "pkey", "pkey name")
	apiSvc := flag.String("svc", "neighbor", "api service name")
	apiReq := flag.String("req", "", "api/read request name")
	Ner_opt := flag.String("opt", "", "api set key(optional) [key=123456789&rpm=60&url=http://yoururl]")
	flag.Parse()
	pkey_name:=*pkeyN

    switch *act {
    case "send":{
	nextroute:=make([]send.NextMsg,1)
	nextroute[0].Addr=*nextAddr
	nextroute[0].Auth=*nextAuth
	sendmsg(nextroute)
	}
    case "gen":{
		mainPub, mainPriv,err:=keygen.Gen_mainkey()
		if err!=nil{
			fmt.Println("mainkey:",err)
			return
		}
		pub, priv, err:=keygen.Gen_pkey()
        if err!=nil{
			fmt.Println("pkey:",err)
			return
		}
		signKey:=keygen.Sig_pkey(pub, mainPriv)
		mustWrite("mainkey.pub", mainPub)
		mustWrite("mainkey.priv", mainPriv)
		mustWrite(pkey_name+".pub", pub)
		mustWrite(pkey_name+".priv", priv)
		mustWrite(pkey_name+".sig", signKey)
		fmt.Println("key generation complete")
		fmt.Println("mainkey.pub :", hex.EncodeToString(mainPub))
		fmt.Println(pkey_name+".pub    :", hex.EncodeToString(pub))
		fmt.Println(pkey_name+".sig    :", hex.EncodeToString(signKey))
	}
    case "base32":{
        data, err := os.ReadFile("mainkey.pub")
		if err != nil {
			fmt.Println("mainkey:",err)
			return
		}
		encoded := base32.StdEncoding.EncodeToString(data)
		fmt.Println("mainkey base32:",strings.ReplaceAll(encoded, "=", ""))
	}
	case "newkey":{
		mainPriv, err := os.ReadFile("mainkey.priv")
		if err != nil {
			fmt.Println("mainkey:",err)
			return
		}
		pub, priv, err:=keygen.Gen_pkey()
        if err!=nil{
			fmt.Println("pkey:",err)
			return
		}
		signKey:=keygen.Sig_pkey(pub, mainPriv)
		mustWrite(pkey_name+".pub", pub)
		mustWrite(pkey_name+".priv", priv)
		mustWrite(pkey_name+".sig", signKey)
		fmt.Println("new pkey generation complete")
		fmt.Println(pkey_name+".pub    :", hex.EncodeToString(pub))
		fmt.Println(pkey_name+".sig    :", hex.EncodeToString(signKey))
	}
	case "des":{
        data, err := os.ReadFile(pkey_name+".pub")
		if err != nil {
			fmt.Println(pkey_name+".pub:",err)
			return
		}
		h := fnv.New64a()
		h.Write(data)
		new_des:=h.Sum64()
		fmt.Println("pkey des:",fmt.Sprintf("%x", new_des))
	}
	case "api":{
        apiAddr:=*nextAddr
		apiToken:=*nextAuth
		if len(apiToken)<8{
			fmt.Println("api token is null")
			return
		}
		if *apiReq==""{
			fmt.Println("api request is null")
			return
		}
		if apiAddr == "http://127.0.0.1:8888" {
			apiAddr="10428"
		}
		if !strings.HasPrefix(apiAddr,"http"){
			if apiAddr == "" {
				apiAddr = "http://127.222.1.16:10428"
			} else {
				apiAddr = "http://127.222.1.16:"+apiAddr
			}
		}
		
		if *apiSvc != "neighbor" {
			url := apiAddr+"/local/api/interface?svc="+*apiSvc+"&req="+url.QueryEscape(*apiReq)+"&token="+apiToken
			resp, err := http.Get(url)
			if err != nil {
				fmt.Println("request api err:",err)
				return
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				fmt.Println("send api request err:",err)
				return
			}
			fmt.Println("api:",string(body))
			return
		}
		
		opt_key,err:= url.ParseQuery(*Ner_opt)
		if err != nil {
			fmt.Println("resolv opt key err:",err)
			return
		}
		
		key:=opt_key.Get("key")
		if key == "" && *apiReq=="list" {
			key="123456789"
		}
		rpm:=opt_key.Get("rpm")
		if rpm == "" {
			rpm="60"
		}
		seturl:=url.QueryEscape(opt_key.Get("url"))
		
		if key==""{
			fmt.Println("ERR: neighbor key is null")
			return
		}
		
		url := apiAddr+"/local/api/interface?svc=neighbor&req="+url.QueryEscape(*apiReq)+"&token="+apiToken+"&key="+url.QueryEscape(key)
		
		if seturl!=""{
			url += "&url="+seturl+"&rpm="+rpm
		}
		resp, err := http.Get(url)
		if err != nil {
			fmt.Println("request api err:",err)
			return
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			fmt.Println("send api request err:",err)
			return
		}
		fmt.Println("api:",string(body))
	}
	case "chk":{
		exePath, err := os.Executable()
		if err != nil {
			fmt.Println("ERR: read path err:",err)
			return
		}
        BaseDir := filepath.Join(filepath.Dir(exePath), "kep-data")
        files, err := filepath.Glob(filepath.Join(BaseDir, "tag_*.idx"))
		if err != nil {
			fmt.Println("ERR: read index err:",err)
			return
		}
		if len(files)==0{
			fmt.Println("ERR: index file not found, path:",BaseDir)
			return
		}
		for _, f := range files {
			fmt.Println("INFO: check index:",f)
			data, err := os.ReadFile(f)
			if err != nil {
				fmt.Println("ERR: read index file:",err)
				return
			}
			if len(data)%65!=0{
				fmt.Println("ERR: index length err ,file:",f)
				return
			}
			if bytes.Contains(data, []byte("\r")) || bytes.Contains(data, []byte("\n\n")) {
				fmt.Println("ERR: index format err ,file:",f)
				return
			}
		}
		fmt.Println("Done: check index: ALL file is OK")
	}
	case "read":{
		exePath, err := os.Executable()
		if err != nil {
			fmt.Println("find path err:",err)
			return
        }
		kepdb.Init_path(filepath.Dir(exePath))
		if len(*apiReq)!=64 {
			fmt.Println("read post err: hash not found,",*apiReq)
			return
		}
		hexs,err:=kepdb.ReadHash(*apiReq)
		if err !=nil {
			fmt.Println("read post err:",err)
			return
		}
		txt,domain,timestamp,point_to,perm,key,_,tag,root,tag2,err:=kepresolv.Resolv(hexs)
		if err !=nil {
			fmt.Println("resolv post err:",err)
			return
		}
		pointTo:=hex.EncodeToString(point_to)
		if pointTo == ""{
			pointTo="null"
		}
		Root:=hex.EncodeToString(root)
		if Root == ""{
			Root="null"
		}
		t := time.Unix(timestamp, 0).Local()
		fmt.Println("\n===========post info===========\n")
		fmt.Println("user:",string(domain))
		fmt.Println("timestamp:",t.Format("2006-01-02 15:04:05"))
		fmt.Println("point to:",pointTo)
		fmt.Println("perm:",perm)
		fmt.Println("key:",key)
		fmt.Println("tag:",tag)
		fmt.Println("root:",Root)
		fmt.Println("tag2:",tag2)
		fmt.Println("\n===========post text===========\n")
		fmt.Println(string(txt))
		return
	}
    default:
        fmt.Println("usage:\n\t-act [send/gen/base32/newkey/des/api/chk/read] -pkey [pkeyName] -addr [http://web] -auth [token]")
    }
}
func sendmsg(nextroute []send.NextMsg){
	send.Send_Init(nextroute,"")
	var mainPub,priv,signKey,pub []byte
	var err error
    mainPub, err = os.ReadFile("mainkey.pub")
    if err != nil {
        fmt.Println("mainkey:",err)
		return
    }
	pub, err = os.ReadFile("pkey.pub")
    if err != nil {
        fmt.Println("pkey:",err)
		return
    }
	
    priv, err = os.ReadFile("pkey.priv")
    if err != nil {
        fmt.Println("pkey:",err)
		return
    }

    signKey, err = os.ReadFile("pkey.sig")
    if err != nil {
        fmt.Println("pkey:",err)
		return
    }
	
	reader := bufio.NewReader(os.Stdin)

    fmt.Print("发帖/回帖(回帖指向上一个hex，发帖输入0): ")
    point_to_type, _ := reader.ReadString('\n')
    point_to_type = strings.TrimSpace(point_to_type)

    fmt.Print("输入贴文正文: ")
    userinput, _ := reader.ReadString('\n')
    userinput = strings.TrimSpace(userinput)
	
	fmt.Print("输入你的域名: ")
    domain_user, _ := reader.ReadString('\n')
    domain_user = strings.TrimSpace(domain_user)
	
    version := byte(1)
    hashtype := byte(1) // 1 = sha256
    typeID := byte(0)
    tag := uint16(1)
    tag2 := tag
    ttl := byte(8)
    compressType := byte(0)

    domain := []byte(domain_user)
    txt := []byte(userinput)
    
	var pointTo []byte
	
	if len(point_to_type) < 16 {
		pointTo = []byte{} // 发帖，无指针
	} else {
		bytes, err := hex.DecodeString(point_to_type)
		if err != nil {
			fmt.Println("Decode point:",err)
			return
		}
		pointTo = bytes
	}

    buf := new(bytes.Buffer)

    buf.WriteByte(version)
    buf.WriteByte(hashtype)
    buf.WriteByte(byte(len(domain)))
    buf.Write(unix40()[:])

    binary.Write(buf, binary.BigEndian, uint16(len(txt)))

    buf.Write(mainPub)
    buf.Write(pub)
    buf.Write(signKey)

    buf.WriteByte(typeID)
    buf.WriteByte(byte(len(pointTo)))
    binary.Write(buf, binary.BigEndian, tag)
    buf.WriteByte(compressType)

    buf.Write(domain)
    buf.Write(pointTo)
    buf.Write(txt)

    h := sha256.Sum256(buf.Bytes())
    tHash := h[:]
    buf.Write(tHash)

    signature := ed25519.Sign(priv, tHash)
    buf.Write(signature)

    binary.Write(buf, binary.BigEndian, tag2)
    buf.WriteByte(ttl)

    msg := buf.Bytes()
	
	err = send.Nextmsg(msg,"")
	if err != nil {
		fmt.Println("send msg err:",err)
	} else {
    fmt.Printf("发送完成\n")
    fmt.Printf("t_hash: %x\n", tHash)
	}
}