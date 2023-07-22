#baby rev             
đầu tiên bỏ file vào ida xong vào hàm main ta thấy so sánh giữa input (username) và string "bossbaby"      
=>> ta có username = "bossbaby"
![image](https://github.com/Ash-Dust/CTF/assets/120457430/04c31b06-7b8d-486e-9d97-a74fe9a75b66)


lại thấy tiếp ở dưới có hàm if so sánh hàm sub_12B2(v5)`*[1]` với 38 nên ta để in ra dòng cuối nên ta mở thử hàm 
![image](https://github.com/Ash-Dust/CTF/assets/120457430/52c37c7d-f311-405a-87f1-4ca57f19eff4)

nhìn từ dưới lên ta thấy hàm này trả về v9 để so sánh với số 38 ngoài kia => v9 là 1 biến đếm tăng dần                 
và password có 38 kí tự     


![image](https://github.com/Ash-Dust/CTF/assets/120457430/15179dd9-c1c8-4772-9d1a-7cd7d8a52ca8)

và từ dòng 28 trở đi t thấy v9 chỉ tăng khi câu `if ( dword_4020[i] == *((_DWORD *)v11 + i) )` của vòng lặp thỏa 1 điều kiện j đấy 
và theo mình hiểu thì `if ( dword_4020[i] == *((_DWORD *)v11 + i) )` sẽ so sánh các kí tự trong string dword_4020 với v11 
nếu nó = nhau thì tăng v9 nếu ko bằng thì bỏ qua =>> cần phải đúng hết các kí tự để v9 tăng lên 38 nếu sai thì kí tự sẽ nhỏ hơn số 38 ngoài kia


nhìn lên trên 1 chút ta thấy v11 được gán giá trị của v6 và có 1 hàm 'sub_1209' lấy giá trị đầu vào là **'s'** và **'v6'** 
![image](https://github.com/Ash-Dust/CTF/assets/120457430/97f760dc-0ae7-4604-8d13-4c255fdb2b41) =>> cứ thử mở thử xem lỡ có flag =))


sau khi mở xong sẽ ra như thế này:                                                                                           
![image](https://github.com/Ash-Dust/CTF/assets/120457430/2156b3bc-d066-4445-8aad-0833b4d059e0)                                          
về cơ bản thì ta có :
 **'s'** sẽ tương đương với **_a1_**  và  **'v6'** sẽ tương đương với **_a2_**

 và hàm này có chức năng(giản lược lại) mã hóa a1 và sau đó gán nó vào a2 r cuối cùng trả về a2( = v6 ) `*[2]`
 **quá trình mã hóa mình sẽ chú thích ở dưới**
 
 thì mình sau đó chỉ cần mã hóa ngược nó sẽ ra được flag
 
 script decode để tìm a2:
 ![image](https://github.com/Ash-Dust/CTF/assets/120457430/0227d440-d8ef-4db1-96e8-45a5b8776eb7)


-----------------------------------------------------------------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------------------------------------------------------------
 `[1]`                                                                                                                                         
![image](https://github.com/Ash-Dust/CTF/assets/120457430/1fe756b9-974b-4b22-b010-6d5919592450)                                           
chú thích thêm ở phần giá trị đầu vào v5 (v5 là input của password mình nhập vào)                                             

![image](https://github.com/Ash-Dust/CTF/assets/120457430/c5d83b6c-73a8-4405-8ba5-ac2a46bd3c34)
  
  
  
  
  
 `[2]`                                                                                                                
 ![image](https://github.com/Ash-Dust/CTF/assets/120457430/ed5b466a-4ee8-4f35-8c3a-2def234353fa)                            
ta thấy đây là 1 vòng lặp thực hiện liên tục và dừng khi biến i đến độ dài của a1:
  
      *(_DWORD *)(4LL * i + a2) = (a1[i] << ((char)i % 7)) + i * i;
      
vế bên trái  '*(_DWORD *)(4LL * i + a2);' về cơ bản (theo như mình hiểu thì nó tóm gọn lại là *a2[i] =))

P/s:~~nó là cái địa chỉ gì gì đó, buffer gì gì đó mà t vẫn méo thể nào thông não được =)~~

và vế bên phải '(a1[i] << ((char)i % 7)) + i * i';' sẽ là 1 kiểu mã hóa kí tự a[1] để gán vào vào *a2[]

P/ss:~~cái dấu "<<" là kiểu dịch trái j j đó t cx méo thể nào thông đc =))~~
nói tóm gọn lại là như bên toán học =))                                                                                                   
chuyển vế đổi dấu:
```
              *a2 = (a1[i] << ((char)i % 7)) + i * i);
          <=> (*a2 - i * i) = a1[i] << ((char)i % 7))
          <=> (*a2 - i * i) >> ((char)i % 7)) = a1[i]
```
sử dụng thuật toán này để tìm ra a1

nhưng ta vẫn chưa có a2 thì làm thế nào để tìm ra a1?

thì đây 'if ( dword_4020[i] == *((_DWORD *)v11 + i) )' sẽ so sánh các kí tự trong string dword_4020* với v11

mà v11 = v6(trước khi mã hóa)

nên nếu v6(a2 sau khi mã hóa) hợp lệ thì đó là flag





