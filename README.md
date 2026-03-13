# Seth
      A Dynamic Blockchain Sharding System with Resilient and Seamless Shard Reconfiguration
      paper: https://ccs2025a.hotcrp.com/doc/ccs2025a-paper756.pdf?cap=hcav756eNAubdJqApSsXnJDucFgJMXB
      

# Quick Start
## Requirements
      g++8.3.0
      cmake3.25.1+

## Run local seth network
      git clone git@github.com:iPoW-Stack/SethPub.git /root/seth && cd /root/seth
	  bash build_third.sh
      bash simple_dep.sh $node_count  
      # node_count like 4, mean create 4 nodes seth network on local machine
	  
## Run customized network
      bash simple_remote.sh $each_machine_node_count $ip_list  
      # each_machine_node_count like 4, mean each machine create 4 nodes. 
      # ip_list like 192.168.0.1,192.168.0.2, mean 2 machine create 2 * 4 nodes seth network
      # machine user must root
      # machine password must Xf4aGbTaf!(for test), you can change it by edit simple_remote.sh

## Transaction test
```
      cd ./cbuild_Release && make txcli
      ./txcli
```

## Start Mining
################################################################
#                SECURITY NOTICE / 安全提示                    #
################################################################

**IMPORTANT / 重要提示:**
> The raw **'Private Key'** listed above is your **ONLY** way to access your funds. 
> Please **SAVE IT** in a secure offline location.
> 上述明文**“私钥”**是您访问资金的**唯一**凭证。请务必将其保存至安全的离线位置。

**WARNING / 警告:**
> **DO NOT** store the raw Private Key on this server. 
> Delete any temporary files or command history containing the key.
> **严禁**在该服务器上存储明文私钥。请删除任何包含该密钥的临时文件或命令历史记录。

**NOTE / 说明:**
> The configuration in **'seth.conf'** uses a **SEALED (encrypted)** version of your key. 
> Even if the config file is leaked, your original private key remains safe and cannot be easily reversed.
> **'seth.conf'** 中的配置使用的是经**密封（加密）**后的密钥。
> 即使配置文件泄露，您的原始私钥仍是安全的，且无法被轻易反推。

################################################################
```
      bash build_third.sh
      bash start_miner.sh <RAW_HEX_PRIVATE_KEY>
```


