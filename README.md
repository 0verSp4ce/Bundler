# Bundler

PE学习小工具，它的作用就是将32位的PE文件的按内存对齐，然后合并所有节，接着新增一个节存放Shellcode，将程序入口位置修改到Shellcode的位置。

使用方法：Bundler.exe PE_FILE SC_FILE

