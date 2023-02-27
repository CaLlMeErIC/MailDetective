import sys
from OSutils import getInputArgs
from MailChecker import MailChecker

if __name__ == '__main__':
    # input_args = ["--file", "testfrom.eml", "--verbose", "True"]
    file = ""
    dir = ""
    save = "Report/"
    verbose = False
    input_args_dict = getInputArgs(sys.argv)

    for each_args in input_args_dict:
        if input_args_dict.get(each_args) is not None:
            globals()[each_args] = input_args_dict.get(each_args)
    if isinstance(verbose, str):
        # verbose参数控制是否打印结果
        if "rue" in verbose:
            verbose = True
    else:
        verbose = False

    if file:
        MailChecker().checkFile(file_path=file, verbose=verbose, save_dir=save)

    if dir:
        MailChecker().checkDir(dir_path=dir, verbose=verbose, save_dir=save)
