package main 
import "fmt" 
import "crypto/rand" 
import "encoding/hex" 
func main() { b:=make([]byte,32);rand.Read(b);fmt.Println(hex.EncodeToString(b)) }
