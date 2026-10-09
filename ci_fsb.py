import os, time, fcntl
d=os.path.join(os.environ["TMPDIR"],"fsb"); os.makedirs(d,exist_ok=True)
def full(fd): fcntl.fcntl(fd,51)
for name,fn in (("F_FULLFSYNC",full),("fsync",os.fsync)):
    t=time.time()
    for i in range(50):
        fd=os.open(os.path.join(d,f"{name}{i}"),os.O_CREAT|os.O_WRONLY); os.write(fd,b"x"*4096); fn(fd); os.close(fd)
        dfd=os.open(d,os.O_RDONLY); fn(dfd); os.close(dfd)
    print(name,"50x(file+dir sync):",round(time.time()-t,2),"s",flush=True)
