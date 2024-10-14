MailReader.py:
读取eml文件的工具类
MailChecker.py:
检测eml文件的工具类
JsonRules:
存放简单的正则规则，以json形式存储
MeatRules:
存放复杂的检测规则，以类的形式存储
Mics:
存放一些之前的脚本和论文等
Report:
默认的存放保存结果报告的文件夹
Samples:
存放一些测试eml文件
MailDetective.py:
用于通过命令行调用MailChecker工具类

MailDetective.py的参数：
--file 指定某个eml文件进行检测
--dir 指定某个文件夹，检测其中所有的以.eml结尾的文件
--save 指定保存结果的文件夹，如不提供默认为Report
--verbose 指定是否打印结果，默认为False

其他细节在博客里：https://blog.csdn.net/qq_43199509/article/details/129244264

测试：
MailDetective.py --dir Samples --verbose True
