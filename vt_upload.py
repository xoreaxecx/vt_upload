# Checks the hash of the file on the VT.com and, depending on the result, sends the file for scanning.
# Dependencies: pip install vt-py colorama
import argparse
import datetime
import hashlib
import operator
import os
import sys
import time
import vt
from shutil import copy

try:
    from colorama import init, Back
except ImportError:
    print('\n#########################################')
    print('Colorama module not found.')
    print('Colors replaced with brackets "[".')
    print('Use "pip install colorama" to add colors.')
    print('#########################################\n')
    input('Press Enter to continue or Ctrl + C to exit...')

    def init():
        pass

    class Back:
        RED = '['
        GREED = '['
        BLACK = '['
        CYAN = '['
        RESET = ']'

DAYS_TO_SCAN_ALLOWED = 3
ALLOWED_TIME_DELTA = 3600 * 24 * DAYS_TO_SCAN_ALLOWED  # seconds in "days_to_scan_allowed" days
CURR_DATE = datetime.datetime.now()
SRC_IS_FILE = True
CLIENT: vt.client.Client
TMP_NAME = 'test.exe'
TMP_FILE_PATH = ''
AV_NAMES = \
    ('Acronis',
     'Ad-Aware',
     'AegisLab',
     'AhnLab-V3',
     'Alibaba',
     'ALYac',
     'Antiy-AVL',
     'APEX',
     'Arcabit',
     'Avast',
     'Avast-Mobile',
     'Avira',
     'Baidu',
     'BitDefender',
     'BitDefenderFalx',
     'BitDefenderTheta',
     'Bkav',
     'CAT-QuickHeal',
     'ClamAV',
     'CMC',
     'Comodo',
     'CrowdStrike',
     'Cybereason',
     'Cylance',
     'Cynet',
     'Cyren',
     'DrWeb',
     'eGambit',
     'Elastic',
     'Emsisoft',
     'ESET-NOD32',
     'F-Secure',
     'FireEye',
     'Fortinet',
     'GData',
     'Gridinsoft',
     'Ikarus',
     'Jiangmin',
     'K7AntiVirus',
     'K7GW',
     'Kaspersky',
     'Kingsoft',
     'Malwarebytes',
     'MAX',
     'MaxSecure',
     'McAfee',
     'McAfee-GW-Edition',
     'Microsoft',
     'MicroWorld-eScan',
     'NANO-Antivirus',
     'Paloalto',
     'Panda',
     'Qihoo-360',
     'Rising',
     'Sangfor',
     'SentinelOne',
     'Sophos',
     'SUPERAntiSpyware',
     'Symantec',
     'SymantecMobileInsight',
     'TACHYON',
     'Tencent',
     'Trapmine',
     'TrendMicro',
     'TrendMicro-HouseCall',
     'Trustlook',
     'VBA32',
     'VIPRE',
     'ViRobot',
     'Webroot',
     'Yandex',
     'Zillya',
     'ZoneAlarm',
     'Zoner')


class Log:
    __path = ''
    __file = None

    @staticmethod
    def init(path):                                      # open log handle
        Log.__path = path
        Log.__file = open(Log.__path, 'a', buffering=1)  # 1 means line buffered
        argv_msg = f'{"-" * 30}\n' \
                   f'{" ".join(sys.argv)}\n' \
                   f'{"-" * 30}'
        Log.write(argv_msg)

    @staticmethod
    def write(message):
        if Log.__file:
            Log.__file.write(f'{message}\n\n')

    @staticmethod
    def close():                                         # close log handle
        if Log.__file:
            Log.__file.close()


class FileSearchInfo:
    def __init__(self, dir_path, file_name):
        self.dir_path = dir_path
        self.file_name = file_name


class ResultInfo:
    def __init__(self, is_target, av_name, category, detect_name, color_open='', color_close=''):
        self.is_target = is_target
        self.av_name = av_name
        self.category = category
        self.detect_name = detect_name
        self.color_open = color_open
        self.color_close = color_close

    # return a string to be output to the console
    def get_out_str(self, name_indent, cat_indent):
        if self.is_target:
            return f'{self.color_open}{self.av_name.ljust(name_indent, " ")}{self.color_close}  -  {self.category.ljust(cat_indent, " ")}  -  {self.detect_name}'
        else:
            return f'{self.av_name.ljust(name_indent, " ")}  -  {self.category.ljust(cat_indent, " ")}  -  {self.detect_name}'

    # return a string to be written to the log
    def get_log_str(self, name_indent, cat_indent):
        return f'{self.av_name.ljust(name_indent, " ")}  -  {self.category.ljust(cat_indent, " ")}  -  {self.detect_name}'


class ScoreInfo:
    def __init__(self, detect_count, log_message, out_message):
        self.detect_count = detect_count
        self.log_message = log_message
        self.out_message = out_message


def exit_program(message=''):
    global TMP_FILE_PATH
    if message:
        print(f'{Back.RED}{message}{Back.RESET}')
        Log.write(message)
    Log.close()
    close_vt_client()
    clean_tmp_file()
    print('Exiting the program...')
    sys.exit(2)


def separate():
    try:
        print('-' * (os.get_terminal_size()[0]))
    except OSError:
        print('-------------------------------')


# print and write the scores of the files to the log
def store_score(file_name, score: ScoreInfo):
    if score.detect_count > 0:
        log_msg = f'{"-" * 100}\n' \
                  f'File name: {file_name}\n' \
                  f'Score:     {score.detect_count}\n' \
                  f'----------\n' \
                  f'{score.log_message}\n' \
                  f'{"-" * 100}'

        out_msg = f'File name: {file_name}\n' \
                  f'Score:     {score.detect_count}\n' \
                  f'----------\n' \
                  f'{score.out_message}'
    else:
        log_msg = f'{"-" * 100}\n' \
                  f'File name: {file_name}\n' \
                  f'Score:     CLEAR\n' \
                  f'{"-" * 100}'

        out_msg = f'File name: {file_name}\n' \
                  f'Score:     {Back.GREEN}CLEAR{Back.RESET}\n' \
                  f'----------\n' \
                  f'{score.out_message}'

    Log.write(log_msg)
    separate()
    print(out_msg)
    separate()


# Save all AV names from VT result to the log as a list
def save_av_names(results):
    av_names = []
    for key in results:
        av_names.append(key)
    av_names = sorted(av_names, key=str.casefold)
    resultstr = "\n\nAV_names = \\\n('" + "',\n'".join(av_names) + "')\n\n"
    Log.write(resultstr)


# collect information from the results received
def get_score(results, targets, file_path, file_name):
    detects = []
    detects_count = 0
    name_max_len = 0  # max length of the name to align
    cat_max_len = 0   # max length of the category to align
    for key in results:
        if targets and key in targets:
            if results[key]['category'] == 'malicious':
                detects_count += 1
                detects.append(ResultInfo(is_target=True,
                                          av_name=key,
                                          category=results[key]['category'],
                                          detect_name=results[key]["result"],
                                          color_open=Back.RED,
                                          color_close=Back.RESET))
            elif results[key]['category'] == 'undetected':
                detects.append(ResultInfo(is_target=True,
                                          av_name=key,
                                          category=results[key]['category'],
                                          detect_name=results[key]["result"],
                                          color_open=Back.GREEN,
                                          color_close=Back.RESET))
            elif results[key]['category'] == 'timeout':
                rescan_count = 1
                rescan_result = results[key]
                while rescan_result['category'] == 'timeout':
                    if rescan_count > 5:
                        break
                    msg = f'Scan result is "timeout".\nRescan {rescan_count}'
                    print(msg)
                    Log.write(msg)
                    rescan = vt_upload_file(file_path)
                    rescan_result = rescan.results[key]
                    rescan_count += 1
                detects.append(ResultInfo(is_target=True,
                                          av_name=key,
                                          category=rescan_result['category'],
                                          detect_name=rescan_result['result'],
                                          color_open=Back.LIGHTMAGENTA_EX,
                                          color_close=Back.RESET))
            else:
                detects.append(ResultInfo(is_target=True,
                                          av_name=key,
                                          category=results[key]['category'],
                                          detect_name=results[key]["result"],
                                          color_open=Back.CYAN,
                                          color_close=Back.RESET))
            if len(key) > name_max_len:
                name_max_len = len(key)
            if len(results[key]['category']) > cat_max_len:
                cat_max_len = len(results[key]['category'])
        elif results[key]['category'] == 'malicious':
            detects_count += 1
            detects.append(ResultInfo(is_target=False,
                                      av_name=key,
                                      category=results[key]['category'],
                                      detect_name=results[key]["result"]))
            if len(key) > name_max_len:
                name_max_len = len(key)
            if len(results[key]['category']) > cat_max_len:
                cat_max_len = len(results[key]['category'])

    log_msg = []
    out_msg = []
    for detect in detects:
        out_msg.append(detect.get_out_str(name_max_len, cat_max_len))
        if detect.is_target:
            log_msg.append(f'{detect.get_log_str(name_max_len, cat_max_len)} << File name: {file_name} - Score: {detects_count} \t << TARGET')
        else:
            log_msg.append(detect.get_log_str(name_max_len, cat_max_len))
    return ScoreInfo(detect_count=detects_count,
                     log_message='\n'.join(log_msg),
                     out_message='\n'.join(out_msg))


def vt_upload_file(file_path):
    global TMP_FILE_PATH
    copy(file_path, TMP_FILE_PATH)

    start_time = time.time()
    start_msg = f'Uploading file: {file_path}'
    print(start_msg)
    with open(TMP_FILE_PATH, "rb") as f:
        analysis = CLIENT.scan_file(f, wait_for_completion=True)
    end_msg = f'Scan time: {int(time.time() - start_time)} sec'
    print(end_msg)
    Log.write(f'{start_msg}\n{end_msg}')
    clean_tmp_file()
    return analysis


def vt_check_file(file_dir, file_name, targets):
    file_path = os.path.join(file_dir, file_name)
    md5 = hashlib.md5(open(file_path, 'rb').read()).hexdigest()
    file_result = get_file_result(md5)
    if file_result is None:
        file_result = vt_upload_file(file_path)
        file_score = get_score(file_result.results, targets, file_path, file_name)
    else:
        need_to_upload = check_upload_is_needed(file_result, md5)
        if need_to_upload:
            file_result = vt_upload_file(file_path)
            file_score = get_score(file_result.results, targets, file_path, file_name)
        else:
            file_score = get_score(file_result.last_analysis_results, targets, file_path, file_name)
    store_score(file_name, file_score)


# check the file was uploaded
def get_file_result(md5_hash):
    global CLIENT
    try:
        file_result = CLIENT.get_object(f"/files/{md5_hash}")
        return file_result
    except vt.error.APIError:
        # so the file was not uploaded
        return None


# check date of the last scan
def check_upload_is_needed(file_result, md5_hash):
    global CURR_DATE, ALLOWED_TIME_DELTA
    need_to_upload = True
    scan_time_delta = CURR_DATE - file_result.last_analysis_date
    if scan_time_delta.total_seconds() < ALLOWED_TIME_DELTA:
        need_to_upload = False
        msg = f'Last analysis data used.\nMD5 = {md5_hash}'
        print(msg)
        Log.write(msg)
    return need_to_upload


def set_vt_client(path_to_key):
    global CLIENT
    with open(path_to_key, 'r') as f:
        vt_key = f.read()
    CLIENT = vt.Client(vt_key.strip())


def close_vt_client():
    global CLIENT
    if 'CLIENT' in globals():
        CLIENT.close()


def clean_tmp_file():
    global TMP_FILE_PATH
    if os.path.exists(TMP_FILE_PATH):
        try:
            os.remove(TMP_FILE_PATH)
        except Exception as e:
            print_error(e)


def show_av_names():
    global AV_NAMES
    print(f'\nAV names ({len(AV_NAMES)}):')
    separate()
    for name in AV_NAMES:
        print(name)
    separate()


def print_error(err):
    print(f'==================================================\n'
          f'{Back.RED}{err}{Back.RESET}\n'
          f'==================================================\n')


def check_dir(dir_path):
    if os.path.exists(dir_path):
        if os.path.isfile(dir_path):
            exit_program(f'Directory path must be specified, but the file path was found: {dir_path}')
    else:
        try:
            os.makedirs(dir_path)
        except Exception as e:
            print_error(e)
            exit_program(f'Can not create directory: {dir_path}')


# set tmp file path to avoid overwriting
def set_tmp_file_path(tmp_dir):
    global TMP_NAME, TMP_FILE_PATH
    tmp_path = os.path.join(tmp_dir, TMP_NAME)
    if os.path.exists(tmp_path):
        counter = 0
        while os.path.exists(tmp_path):
            counter += 1
            tmp_path = os.path.join(tmp_dir, f'{TMP_NAME}_{counter}')
        TMP_NAME = f'{TMP_NAME}_{counter}'
    TMP_FILE_PATH = os.path.join(tmp_dir, TMP_NAME)


def check_args(initargs):
    global SRC_IS_FILE, TMP_FILE_PATH, DAYS_TO_SCAN_ALLOWED
    # print target AV names
    if initargs.names:
        show_av_names()
        exit_program()
    # check source file
    if not initargs.src:
        exit_program('Source path "-src" is not specified.')
    if os.path.exists(initargs.src):
        if os.path.isdir(initargs.src):
            SRC_IS_FILE = False
    else:
        exit_program(f'Can not access source file or directory: {initargs.src}')
    # set buffer directory
    if initargs.buf:
        check_dir(initargs.buf)
    else:
        initargs.buf = os.path.split(initargs.src)[0]
    # set path for a tmp file
    set_tmp_file_path(initargs.buf)
    # check specified AV names
    if initargs.target:
        warnings = []
        for t in initargs.target:
            if t not in AV_NAMES:
                warnings.append(f'Selected invalid target name: {Back.RED}{t}{Back.RESET}')
        if warnings:
            for w in warnings:
                print(w)
            exit_program()
    # check key file
    if not initargs.key:
        initargs.key = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'key.txt')
    if not os.path.exists(initargs.key) or os.path.isdir(initargs.key):
        exit_program(f'Can not access key file: {initargs.key}')
    # check log directory
    if not initargs.log:
        log_name = f'vt_log_{int(time.time())}.txt'
        log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vt_logs')
        initargs.log = os.path.join(log_dir, log_name)
    else:
        log_dir = os.path.split(initargs.log)[0]
    check_dir(log_dir)
    # set extensions
    if initargs.ext:
        initargs.ext = tuple(initargs.ext)
    # check allowed interval
    if initargs.d < 0:
        exit_program(f'Invalid value for switch "-d": {initargs.d}')
    else:
        DAYS_TO_SCAN_ALLOWED = initargs.d


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='VT upload')
    parser.add_argument('-names', action='store_true', help='print all target AV names and exit.')
    parser.add_argument('-src', metavar='path/to/source', type=str, help='path to source file or directory.')
    parser.add_argument('-key', metavar='path/to/key.txt', type=str, help='path to key file. "*script_dir/key.txt" is default.')
    parser.add_argument('-log', metavar='path/to/log.txt', type=str, help='path to log file. "*script_dir/vt_logs/log*.txt" is default.')
    parser.add_argument('-buf', metavar='path/to/tmp/dir', type=str, help='path to tmp dir. "*source/file/dir" is default.')
    parser.add_argument('-t', dest='target', metavar='target_AV', action='append', default=None,
                        help='highlight selected AV names. Multiple "-t" supported.')
    parser.add_argument('-e', dest='ext', metavar='.ext', action='append', default='',
                        help='file extension to process. Omit for all, multiple "-e" supported.')
    parser.add_argument('-d', metavar='int', type=int, default=3, help='days allowed since last scan to not upload. 3 is default.')
    args = parser.parse_args()

    timer = time.time()
    init()                      # Colorama init
    check_args(args)            # Check arguments
    Log.init(args.log)          # Create log file
    set_vt_client(args.key)     # VT client init

    if SRC_IS_FILE:
        src_dir = os.path.split(args.src)[0]
        src_name = os.path.split(args.src)[1]
        vt_check_file(src_dir, src_name, args.target)
    else:
        search_results = []
        for dirpath, dirnames, filenames in os.walk(args.src):
            for filename in [f for f in filenames if f.endswith(args.ext)]:
                search_results.append(FileSearchInfo(dirpath, filename))

        search_results.sort(key=operator.attrgetter('file_name'))
        for result in search_results:
            vt_check_file(result.dir_path, result.file_name, args.target)

    delta = datetime.timedelta(seconds=(time.time() - timer))
    total_time_msg = f'Total time spent: {str(delta)}'
    print(total_time_msg)
    Log.write(total_time_msg)
    close_vt_client()
    clean_tmp_file()
    Log.close()
