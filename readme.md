#aqua  
  
自动检测要访问的网站是否被墙并选择直连或走相应子代理的父级http代理服务器.  
一直觉得怎么就没人造这样一个轮子,然后写到一半发现其实有人写了...(https://github.com/cyfdecyf/cow)  
  
* 2016-07-22  
现已支持子http和socks代理,也就是说子代理可以接shadowsocks,在aqua.json设置即可.  
父代理端口默认为2048,可在aqua.py的最后一行修改.