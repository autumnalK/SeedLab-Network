# <center> Firewall Evasion Lab Report </center>

## Task 1: VM Setup

VM1	VPN Client		10.0.2.4

VM2	VPN Server	   10.0.2.7

## Task 2: Set up Firewall

```sh
$ sudo ufw deny out on enp0s3 from 10.0.2.4 to 202.120.224.81
```

 ![image-20201203193743115](C:\Users\73716\AppData\Roaming\Typora\typora-user-images\image-20201203193743115.png)

## Task 3: Bypassing Firewall using VPN

### Step 1: Run VPN Server

```sh
$ make
$ sudo ./vpnserver
```

 ![image-20201203194858390](C:\Users\73716\AppData\Roaming\Typora\typora-user-images\image-20201203194858390.png) 

```sh
$ sudo ifconfig tun0 192.168.56.1/24 up
$ sudo sysctl net.ipv4.ip_forward=1
```

 ![image-20201203191519938](C:\Users\73716\AppData\Roaming\Typora\typora-user-images\image-20201203191519938.png)

### Step 2: Run VPN Client

```c
// vpnclient.c line 12
#define SERVER_IP "127.0.0.1" --> #define SERVER_IP "10.0.2.7" 
```
```sh
$ make
$ sudo ./vpnclient
```

```sh
$ sudo ifconfig tun0 192.168.56.5/24 up
```

 ![image-20201203191753046](C:\Users\73716\AppData\Roaming\Typora\typora-user-images\image-20201203191753046.png)

### Step 3: Set Up Routing on Client and Server VMs

```sh
# Client VM
$ sudo route add -net 202.120.224.0/24 tun0
$ sudo route add -net 192.168.56.0/24 tun0

# Server VM
$ sudo route add -net 192.168.56.0/24 tun0
```

### Step 4: Set Up NAT on Server VM

```sh
# Server VM
$ sudo iptables -F
$ sudo iptables -t nat -F
$ sudo iptables -t nat -A POSTROUTING -j MASQUERADE -o enp0s3
# -F 清空规则链
# -t 表名(raw、mangle、nat、filter)
# -A 追加规则
# -j 指定如何进行处理
# -o 匹配出口网卡流出的数据
```

```sh
# Demonstration on Clinet VM
$ ping www.fudan.edu.cn -c 1
```

![image-20201203194253387](C:\Users\73716\AppData\Roaming\Typora\typora-user-images\image-20201203194253387.png)

#### Wireshark of different interfaces on client VM

##### Interface tun0

从tun0接口的数据包来看，ping的数据流是在给client VM上的tun0分配的IP地址和目的域名的IP地址之间传输的。

![image-20201203194341853](C:\Users\73716\AppData\Roaming\Typora\typora-user-images\image-20201203194341853.png)

##### Interface enp0s3

从enp0s3接口可以看到，实际上是10.0.2.7作为10.0.2.4和目标域名之间的中介完成了这次ping的请求和响应。10.0.2.4发出的ping请求和收到的ping响应实际上是发给10.0.2.7的，然后由10.0.2.7向目标域名发送真正的ping请求并将得到的ping响应发回给10.0.2.4完成这一次ping命令。

![image-20201203194428427](C:\Users\73716\AppData\Roaming\Typora\typora-user-images\image-20201203194428427.png)

##### Interface any

从any端口可以看到tun0接口的以为的ping命令和实际上10.0.2.4和10.0.2.7的交互的先后顺序。

![image-20201203194510434](C:\Users\73716\AppData\Roaming\Typora\typora-user-images\image-20201203194510434.png)