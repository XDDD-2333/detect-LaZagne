# detect-LaZagne

dt_* : bpftrace脚本
    
* dt_open.bt: 用于对open调用进行检测
* dt_stat.bt: 对stat相关调用和open调用同时进行检测
* dt_memory.bt: 用于检测ptrace, mprotect (目前并未用到)

solve.py : bpftrace序列处理脚本(处理获取到的bpftrace序列, 检测逻辑见源代码注释)

usege:
```
sudo bpftrace dt_stat.bt | python3 solve.py
```
