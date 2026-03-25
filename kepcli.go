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
	act := flag.String("act", "", "tool action [send/gen/base32/newkey/des]")
    nextAddr := flag.String("addr", "http://127.0.0.1:8888", "send msg addr")
	nextAuth := flag.String("auth", "12345678", "send msg auth")
	pkeyN := flag.String("pkey", "pkey", "pkey name")
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
    default:
        fmt.Println("usage:\n\t-act [send/gen/base32/newkey] -pkey [pkeyName] -addr [http://web] -auth [token]")
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