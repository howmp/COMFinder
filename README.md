# COMFinder

## IDA plugin for COM

### 这是一个IDA的插件，依赖于IDAPython，用于查找标记COM组件中函数

## 效果图

左侧为IDA中效果，右侧对比了ComRaider

![comfinder](comfinder.png)

## 原理

1. 在IDAPython中通过pywin32的pythoncom获取COM组件中的原型

1. 使用独立的程序获取COM组件中原型对应的虚表

    **特别注意：由于需要加载dll之后获取虚表，所以千万不要用于恶意程序分析**

## 安装

1. 安装IDA的时候，要勾选IDAPython

1. 用IDAPython的pip，安装pywin32

    默认情况下，使用命令：`C:\python27-x64\Scripts\pip.exe install pywin32`

1. 将bin目录三个文件复制到插件目录

    默认情况下，在这个目录：`C:\Program Files\IDA 7.0\plugins`