# Computer_Virus_Lab_2
23spring-computer virus lab, project 2
文件说明： 根目录：

inject.cpp和shellcode.cpp，后者是病毒载荷代码（已完成进阶任务）
infect程序设计文档
编译说明，含代码环境及编译运行说明
Test-x86.exe，未感染的T程序
Test-x86-1.exe和Test-x86-2.exe，未感染的其余测试程序，用于测试T程序的感染能力
可执行程序及测试说明
可执行程序及测试说明目录：

inject-final.exe，已完成进阶任务的inject.exe，运行后会感染Test-x86.exe
shellcode-final.c，从shellcode.exe提取的.zpy节的十六进制码形式
shellcode-final.exe，shellcode.cpp生成的shellcode.exe
Test-x86.exe，未感染的T程序
使用时，先将Test-x86.exe复制进结果文件目录内，执行inject-final.exe，此时Test-x86.exe被感染，生成学号为2020302181165（组长学号）文件。 如果想测试已感染Test-x86.exe程序的传染能力，复制任意PE格式.exe文件（如Test-x86-1.exe）进至该目录，执行Test-x86.exe即可。 想测试二次传染文件的传染能力操作同上。

注：运行每个程序后请删除2020302181165文件后再运行其它exe文件，同时注意运行Test-x86.exe后，inject-final.exe也会被感染。
