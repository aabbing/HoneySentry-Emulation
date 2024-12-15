#!/usr/bin/env python3

"""
Module that performs extraction. For usage, refer to documentation for the class
'Extractor'. This module can also be executed directly,
e.g. 'extractor.py <input> <output>'.
"""

import argparse
import hashlib
import multiprocessing
import os
import shutil
import tempfile
import traceback
import pathlib
import time
import subprocess
import json

import magic
#import binwalk

class Extractor(object):
    """
    Class that extracts kernels and filesystems from firmware images, given an
    input file or directory and output directory.
    """

    # Directories that define the root of a UNIX filesystem, and the
    # appropriate threshold condition
    UNIX_DIRS = ["bin", "etc", "dev", "home", "lib", "mnt", "opt", "root",
                 "run", "sbin", "tmp", "usr", "var"]
    UNIX_THRESHOLD = 4

    # Lock to prevent concurrent access to visited set. Unfortunately, must be
    # static because it cannot be pickled or passed as instance attribute.
    visited_lock = multiprocessing.Lock()

    def __init__(self, indir, outdir=None, rootfs=True, kernel=True,
                 numproc=True, server=None, brand=None, debug=False):
        # Input firmware update file or directory
        self._input = os.path.abspath(indir)
        # Output firmware directory
        self.output_dir = os.path.abspath(outdir) if outdir else None

        # Whether to attempt to extract kernel
        self.do_kernel = kernel
        self.kernel_done = False

        # Whether to attempt to extract root filesystem
        self.do_rootfs = rootfs
        self.rootfs_done = False

        # Brand of the firmware
        self.brand = brand

        # Hostname of SQL server
        self.database = server

        self.debug = debug

        # Worker pool.
        self._pool = multiprocessing.Pool() if numproc else None

        # Set containing MD5 checksums of visited items
        self.visited = dict()

        # List containing tagged items to extract as 2-tuple: (tag [e.g. MD5],
        # path)
        self._list = list()

    def __getstate__(self):
        """
        Eliminate attributes that should not be pickled.
        """
        self_dict = self.__dict__.copy()
        del self_dict["_pool"]
        del self_dict["_list"]
        return self_dict

    @staticmethod
    def io_dd(indir, offset, size, outdir):
        """
        Given a path to a target file, extract size bytes from specified offset
        to given output file.
        """
        if not size:
            return

        with open(indir, "rb") as ifp:
            with open(outdir, "wb") as ofp:
                ifp.seek(offset, 0)
                ofp.write(ifp.read(size))

    @staticmethod
    def magic(indata, mime=False):
        """
        Performs file magic while maintaining compatibility with different
        libraries.
        """

        try:
            if mime:
                mymagic = magic.open(magic.MAGIC_MIME_TYPE)
            else:
                mymagic = magic.open(magic.MAGIC_NONE)
            mymagic.load()
        except AttributeError:
            mymagic = magic.Magic(mime)
            mymagic.file = mymagic.from_file

        try:
            return mymagic.file(indata)
        except magic.MagicException:
            return None

    @staticmethod
    def io_md5(target):
        """
        Performs MD5 with a block size of 64kb.
        """
        blocksize = 65536
        hasher = hashlib.md5()

        with open(target, 'rb') as ifp:
            buf = ifp.read(blocksize)
            while buf:
                hasher.update(buf)
                buf = ifp.read(blocksize)
            return hasher.hexdigest()

    @staticmethod
    def io_rm(target):
        """
        Attempts to recursively delete a directory.
        """
        shutil.rmtree(target, ignore_errors=True, onerror=Extractor._io_err)

    @staticmethod
    def _io_err(function, path, excinfo):
        """
        Internal function used by '_rm' to print out errors.
        """
        print(("!! %s: Cannot delete %s!\n%s" % (function, path, excinfo)))

    @staticmethod
    def io_find_rootfs(start, recurse=True):
        """
        Attempts to find a Linux root directory.
        """

        # Recurse into single directory chains, e.g. jffs2-root/fs_1/.../
        path = start
        while (len(os.listdir(path)) == 1 and
               os.path.isdir(os.path.join(path, os.listdir(path)[0]))):
            path = os.path.join(path, os.listdir(path)[0])

        # count number of unix-like directories
        count = 0
        for subdir in os.listdir(path):
            if subdir in Extractor.UNIX_DIRS and \
                os.path.isdir(os.path.join(path, subdir)) and \
                    len(os.listdir(os.path.join(path, subdir))) > 0:
                count += 1

        # check for extracted filesystem, otherwise update queue
        if count >= Extractor.UNIX_THRESHOLD:
            return (True, path)

        # in some cases, multiple filesystems may be extracted, so recurse to
        # find best one
        if recurse:
            for subdir in os.listdir(path):
                if os.path.isdir(os.path.join(path, subdir)):
                    res = Extractor.io_find_rootfs(os.path.join(path, subdir),
                                                   False)
                    if res[0]:
                        return res

        return (False, start)

    def extract(self):
        """
        Perform extraction of firmware updates from input to tarballs in output
        directory using a thread pool.
        """
        if os.path.isdir(self._input):
            for path, _, files in os.walk(self._input):
                for item in files:
                    self._list.append(os.path.join(path, item))
        elif os.path.isfile(self._input):
            self._list.append(self._input)

        if self.output_dir and not os.path.isdir(self.output_dir):
            os.makedirs(self.output_dir)

        if self._pool:
            # since we have to handle multiple files in one firmware image, it
            # is better to use chunk_size=1
            chunk_size = 1
            list(self._pool.imap_unordered(self._extract_item, self._list,
                                           chunk_size))
        else:
            for item in self._list:
                self._extract_item(item)

    def _extract_item(self, path):
        """
        Wrapper function that creates an ExtractionItem and calls the extract()
        method.
        """

        ExtractionItem(self, path, 0, None, self.debug).extract()

class ExtractionItem(object):
    """
    Class that encapsulates the state of a single item that is being extracted.
    """

    # Maximum recursion breadth and depth
    RECURSION_BREADTH = 10
    RECURSION_DEPTH = 3
    database = None

    def __init__(self, extractor, path, depth, tag=None, debug=False):
        # Temporary directory
        self.temp = None

        # Recursion depth counter
        self.depth = depth

        # Reference to parent extractor object
        self.extractor = extractor

        # File path
        self.item = path

        self.debug = debug

        # Database connection
        if self.extractor.database:
            import psycopg2
            self.database = psycopg2.connect(database="firmware",
                                             user="firmadyne",
                                             password="firmadyne",
                                             host=self.extractor.database)

        # Checksum
        self.checksum = Extractor.io_md5(path)

        # Tag
        self.tag = tag if tag else self.generate_tag()

        # Output file path and filename prefix
        self.output = os.path.join(self.extractor.output_dir, self.tag) if \
                                   self.extractor.output_dir else None

        # Status, with terminate indicating early termination for this item
        self.terminate = False
        self.status = None
        self.update_status()

    def __del__(self):
        if self.database:
            self.database.close()

        if self.temp:
            self.printf(">> Cleaning up %s..." % self.temp)
            #Extractor.io_rm(self.temp)

    def printf(self, fmt):
        """
        Prints output string with appropriate depth indentation.
        """
        if self.debug:
            print(("\t" * self.depth + fmt))
        pass

    def generate_tag(self):
        """
        Generate the filename tag.
        """
        if not self.database:
            return os.path.basename(self.item) + "_" + self.checksum

        try:
            image_id = None
            cur = self.database.cursor()
            if self.extractor.brand:
                brand = self.extractor.brand
            else:
                brand = os.path.relpath(self.item).split(os.path.sep)[0]
            cur.execute("SELECT id FROM brand WHERE name=%s", (brand, ))
            brand_id = cur.fetchone()
            if not brand_id:
                cur.execute("INSERT INTO brand (name) VALUES (%s) RETURNING id",
                            (brand, ))
                brand_id = cur.fetchone()
            if brand_id:
                cur.execute("SELECT id FROM image WHERE hash=%s",
                            (self.checksum, ))
                image_id = cur.fetchone()
                if not image_id:
                    cur.execute("INSERT INTO image (filename, brand_id, hash) \
                                VALUES (%s, %s, %s) RETURNING id",
                                (os.path.basename(self.item), brand_id[0],
                                 self.checksum))
                    image_id = cur.fetchone()
            self.database.commit()
        except BaseException:
            traceback.print_exc()
            self.database.rollback()
        finally:
            if cur:
                cur.close()

        if image_id:
            self.printf(">> Database Image ID: %s" % image_id[0])

        return str(image_id[0]) if \
               image_id else os.path.basename(self.item) + "_" + self.checksum

    def get_kernel_status(self):
        """
        Get the flag corresponding to the kernel status.
        """
        return self.extractor.kernel_done

    def get_rootfs_status(self):
        """
        Get the flag corresponding to the root filesystem status.
        """
        return self.extractor.rootfs_done

    def update_status(self):
        """
        Updates the status flags using the tag to determine completion status.
        """
        kernel_done = os.path.isfile(self.get_kernel_path()) \
            if self.extractor.do_kernel and self.output \
            else not self.extractor.do_kernel

        rootfs_done = os.path.isfile(self.get_rootfs_path()) \
            if self.extractor.do_rootfs and self.output \
            else not self.extractor.do_rootfs

        self.status = (kernel_done, rootfs_done)
        self.extractor.kernel_done = kernel_done
        self.extractor.rootfs_done = rootfs_done

        if self.database and kernel_done and self.extractor.do_kernel:
            self.update_database("kernel_extracted", "True")

        if self.database and rootfs_done and self.extractor.do_rootfs:
            self.update_database("rootfs_extracted", "True")

        return self.get_status()

    def update_database(self, field, value):
        """
        Update a given field in the database.
        """
        ret = True
        if self.database:
            try:
                cur = self.database.cursor()
                cur.execute("UPDATE image SET " + field + "='" + value +
                            "' WHERE id=%s", (self.tag, ))
                self.database.commit()
            except BaseException:
                ret = False
                traceback.print_exc()
                self.database.rollback()
            finally:
                if cur:
                    cur.close()
        return ret

    def get_status(self):
        """
        Returns True if early terminate signaled, extraction is complete,
        otherwise False.
        """
        return True if self.terminate or all(i for i in self.status) else False

    def get_kernel_path(self):
        """
        Return the full path (including filename) to the output kernel file.
        """
        return self.output + ".kernel" if self.output else None

    def get_rootfs_path(self):
        """
        Return the full path (including filename) to the output root filesystem
        file.
        """
        return self.output + ".tar.gz" if self.output else None

    def extract(self):
        """
        Perform the actual extraction of firmware updates, recursively. Returns
        True if extraction complete, otherwise False.
        """
        self.printf("\n" + self.item.encode("utf-8", "replace").decode("utf-8"))

        # 检查是否完成提取
        if self.get_status():
            self.printf(">> Skipping: completed!")
            return True

        # 检查递归深度是否超出限制
        if self.depth > ExtractionItem.RECURSION_DEPTH:
            self.printf(">> Skipping: recursion depth %d" % self.depth)
            return self.get_status()

        # 检查 checksum 是否已被访问过
        self.printf(">> MD5: %s" % self.checksum)
        with Extractor.visited_lock:
            if (self.checksum in self.extractor.visited and
                    self.extractor.visited[self.checksum] == self.status):
                self.printf(">> Skipping: %s..." % self.checksum)
                return self.get_status()
            else:
                self.extractor.visited[self.checksum] = self.status

        # 检查文件类型是否被黑名单阻止
        #if self._check_blacklist():
            #return self.get_status()

        # 创建临时工作目录
        self.temp = tempfile.mkdtemp()

        # 切换到临时目录
        os.chdir(self.temp)

        try:
            self.printf(">> Tag: %s" % self.tag)
            self.printf(">> Temp: %s" % self.temp)
            self.printf(">> Status: Kernel: %s, Rootfs: %s, Do_Kernel: %s, \
                Do_Rootfs: %s" % (self.get_kernel_status(),
                                self.get_rootfs_status(),
                                self.extractor.do_kernel,
                                self.extractor.do_rootfs))

            # 使用 binwalk 的 Shell 版进行扫描和提取
            result_file = os.path.join(self.temp, "binwalk_result.json")
            #command = f"binwalk -eq --log={result_file} {self.item}"
            #subprocess.run(command, shell=True, check=True)
            command = ["binwalk", "-eq", f"--log={result_file}", self.item]
            subprocess.run(command, check=True)

            # 读取并解析 binwalk 输出的 JSON 结果
            with open(result_file, 'r') as f:
                results = json.load(f)

            for analysis in results:
                file_path = analysis['Analysis']['file_path']
                file_map = analysis['Analysis']['file_map']
                extractions = analysis['Analysis'].get('extractions', {})

                for entry in file_map:
                    offset = entry['offset']
                    desc = entry['description']
                    print(f"\033[1;31m{desc}\033[0m")
                    dir_name = extractions.get(entry['id'], {}).get('output_directory', '')
                    print(f"\033[1;32m{dir_name}\033[0m")

                    # 保留原有的逻辑
                    self.printf('========== Depth: %d ===============' % self.depth)
                    self.printf("Name: %s" % self.item)
                    self.printf("Desc: %s" % desc)
                    self.printf("Directory: %s" % dir_name)

                    self._check_firmware(offset, desc)

                    if not self.get_rootfs_status():
                        self._check_rootfs(dir_name, desc)

                    if not self.get_kernel_status():
                        self._check_kernel(dir_name, desc)

                    if self.update_status():
                        self.printf(">> Skipping: completed!")
                        return True
                    else:
                        self._check_recursive(dir_name, desc)

        except Exception:
            print("ERROR: ", self.item)
            print("command: ", command)
            print("dir_name: ", dir_name)
            print("file_path: ", file_path)
            traceback.print_exc()

        return False

    def _check_blacklist(self):
        """
        Check if this file is blacklisted for analysis based on file type.
        """
        real_path = os.path.realpath(self.item)

#        print ("------ blacklist checking --------------")
#        print (self.item)
#        print (real_path)
        # First, use MIME-type to exclude large categories of files
        filetype = Extractor.magic(real_path.encode("utf-8", "surrogateescape"),
                                   mime=True)
#        print (filetype)
        if filetype:
            if any(s in filetype for s in ["application/x-executable",
                                           "application/x-dosexec",
                                           "application/x-object",
                                           "application/x-sharedlib",
                                           "application/pdf",
                                           "application/msword",
                                           "image/", "text/", "video/"]):
                self.printf(">> Skipping: %s..." % filetype)
                return True

        # Next, check for specific file types that have MIME-type
        # 'application/octet-stream'
        filetype = Extractor.magic(real_path.encode("utf-8", "surrogateescape"))
        if filetype:
            if any(s in filetype for s in ["executable", "universal binary",
                                           "relocatable", "bytecode", "applet",
                                           "shared"]):
                self.printf(">> Skipping: %s..." % filetype)
                return True

#        print (filetype)
#        print ('-=----------------------------')
        # Finally, check for specific file extensions that would be incorrectly
        # identified
        black_lists = ['.dmg', '.so', '.so.0']
        for black in black_lists:
            if self.item.endswith(black):
                self.printf(">> Skipping: %s..." % (self.item))
                return True

        return False

    def _check_firmware(self, offset, desc):
        """
        If this file is of a known firmware type, directly attempt to extract
        the kernel and root filesystem.
        """
        #dir_name = module.extractor.directory
        #desc = entry.description
        if 'header' in desc:
            # uImage
            if "uImage header" in desc:
                if not self.get_kernel_status() and "OS Kernel Image" in desc:
                    kernel_offset = offset + 64
                    kernel_size = 0

                    for stmt in desc.split(','):
                        if "image size:" in stmt:
                            kernel_size = int(''.join(
                                i for i in stmt if i.isdigit()), 10)

                    if kernel_size != 0 and kernel_offset + kernel_size \
                        <= os.path.getsize(self.item):
                        self.printf(">>>> %s" % desc)

                        tmp_fd, tmp_path = tempfile.mkstemp(dir=self.temp)
                        os.close(tmp_fd)
                        Extractor.io_dd(self.item, kernel_offset,
                                        kernel_size, tmp_path)
                        kernel = ExtractionItem(self.extractor, tmp_path,
                                                self.depth, self.tag, self.debug)
                        return kernel.extract()
                # elif "RAMDisk Image" in entry.description:
                #     self.printf(">>>> %s" % entry.description)
                #     self.printf(">>>> Skipping: RAMDisk / initrd")
                #     self.terminate = True
                #     return True

            # TP-Link or TRX
            elif not self.get_kernel_status() and \
                not self.get_rootfs_status() and \
                "rootfs offset: " in desc and "kernel offset: " in desc:
                image_size = os.path.getsize(self.item)
                header_size = 0
                kernel_offset = 0
                kernel_size = 0
                rootfs_offset = 0
                rootfs_size = 0

                for stmt in desc.split(','):
                    if "header size" in stmt:
                        header_size = int(stmt.split(':')[1].split()[0])
                    elif "kernel offset:" in stmt:
                        kernel_offset = int(stmt.split(':')[1], 16)
                    elif "kernel length:" in stmt:
                        kernel_size = int(stmt.split(':')[1], 16)
                    elif "rootfs offset:" in stmt:
                        rootfs_offset = int(stmt.split(':')[1], 16)
                    elif "rootfs length:" in stmt:
                        rootfs_size = int(stmt.split(':')[1], 16)

                # add entry offset
                kernel_offset += offset
                rootfs_offset += offset + header_size

                # compute sizes if only offsets provided
                if rootfs_offset < kernel_offset:
                    if rootfs_size == 0:
                        rootfs_size = kernel_offset - rootfs_offset
                    if kernel_size == 0:
                        kernel_size = image_size - kernel_offset
                elif rootfs_offset > kernel_offset:
                    if kernel_size == 0:
                        kernel_size = rootfs_offset - kernel_offset
                    if rootfs_size == 0:
                        rootfs_size = image_size - rootfs_offset

                self.printf('image size: %d' % image_size)
                self.printf('rootfs offset: %d' % rootfs_offset)
                self.printf('rootfs size: %d' % rootfs_size)
                self.printf('kernel offset: %d' % kernel_offset)
                self.printf('kernel size: %d' % kernel_size)

                # ensure that computed values are sensible
                if kernel_size > 0 and rootfs_size > 0 and \
                        kernel_offset + kernel_size <= image_size and \
                        rootfs_offset + rootfs_size <= image_size:
                    self.printf(">>>> %s" % desc)

                    tmp_fd, tmp_path = tempfile.mkstemp(dir=self.temp)
                    os.close(tmp_fd)
                    Extractor.io_dd(self.item, kernel_offset, kernel_size,
                                    tmp_path)
                    kernel = ExtractionItem(self.extractor, tmp_path,
                                            self.depth, self.tag, self.debug)
                    kernel.extract()

                    tmp_fd, tmp_path = tempfile.mkstemp(dir=self.temp)
                    os.close(tmp_fd)
                    Extractor.io_dd(self.item, rootfs_offset, rootfs_size,
                                    tmp_path)
                    rootfs = ExtractionItem(self.extractor, tmp_path,
                                            self.depth, self.tag, self.debug)
                    rootfs.extract()
                    return True
        return False

    def _check_kernel(self, dir_name, desc):
        """
        If this file contains a kernel version string, assume it is a kernel.
        Only Linux kernels are currently extracted.
        """
        #dir_name = module.extractor.directory
        #desc = entry.description
        if 'kernel' in desc:
            if self.get_kernel_status(): return True
            else:
                if "kernel version" in desc:
                    self.update_database("kernel_version", desc)
                    if "Linux" in desc:
                        if self.get_kernel_path():
                            shutil.copy(self.item, self.get_kernel_path())
                        else:
                            self.extractor.do_kernel = False
                        self.printf(">>>> %s" % desc)
                        return True
                    # VxWorks, etc
                    else:
                        self.printf(">>>> Ignoring: %s" % desc)
        return False

    def _check_rootfs(self, dir_name, desc):
        """
        If this file contains a known filesystem type, extract it.
        """
        #dir_name = module.extractor.directory
        #desc = entry.description
        if 'filesystem' in desc or 'archive' in desc or 'compressed' in desc or 'SquashFS' in desc or 'image' in desc:
            if self.get_rootfs_status(): return True
            else:
                if dir_name:
                    print(f"\033[1;33m{dir_name}\033[0m")
                    unix = Extractor.io_find_rootfs(dir_name)
                    if not unix[0]:
                        self.printf(">>>> Extraction failed!")
                        return False

                    self.printf(">>>> Found Linux filesystem in %s!" % unix[1])
                    #print(f"\033[1;33m Found Linux filesystem \033[0m")
                    if self.output:
                        print(f"\033[1;33m{unix[0]}\033[0m")
                        print(f"\033[1;33m{unix[1]}\033[0m")
                        print(f"\033[1;34m{self.output}\033[0m")
                        shutil.make_archive(self.output, "gztar", root_dir=unix[1])
                    else:
                        self.extractor.do_rootfs = False
                    return True
        return False

    # treat both archived and compressed files using the same pathway. this is
    # because certain files may appear as e.g. "xz compressed data" but still
    # extract into a root filesystem.
    def _check_recursive(self, dir_name, desc):
        """
        Unified implementation for checking both "archive" and "compressed"
        items.
        """
        #dir_name = module.extractor.directory
        #desc = entry.description
        # filesystem for the netgear WNR2000 firmware (kernel in Squashfs)
        if 'filesystem' in desc or 'file system' in desc or 'archive' in desc or 'compressed' in desc or 'TRX' in desc or 'firmware' in desc or 'image' in desc:
        #if dir_name:
            if dir_name:
                self.printf(">> Recursing into %s ..." % desc)
                count = 0
                for root, dirs, files in os.walk(dir_name):
                    # sort both descending alphabetical and increasing
                    # length
                    files.sort()
                    files.sort(key=len)
                    if (not self.extractor.do_rootfs or self.get_rootfs_status()) and 'bin' in dirs and 'lib' in dirs:
                        break

                    # handle case where original file name is restored; put
                    # it to front of queue
                    if desc and "original file name:" in desc:
                        orig = None
                        for stmt in desc.split(","):
                            if "original file name:" in stmt:
                                orig = stmt.split("\"")[1]
                        if orig and orig in files:
                            files.remove(orig)
                            files.insert(0, orig)

                    for filename in files:
    #                        if count > ExtractionItem.RECURSION_BREADTH:
    #                            self.printf(">> Skipping: recursion breadth %d"\
    #                                % ExtractionItem.RECURSION_BREADTH)
    #                            return False

                        path = os.path.join(root, filename)
                        if not pathlib.Path(path).is_file():
                            continue
                        new_item = ExtractionItem(self.extractor,
                                                    path,
                                                    self.depth + 1,
                                                    self.tag,
                                                    self.debug)
                        if new_item.extract():
                            if self.update_status():
                                return True

                        count += 1
        return False

def psql_check(psql_ip):
    try:
        import psycopg2
        psycopg2.connect(database="firmware",
                         user="firmadyne",
                         password="firmadyne",
                         host=psql_ip)

        return True

    except:
        return False

def main():
    parser = argparse.ArgumentParser(description="Extracts filesystem and \
        kernel from Linux-based firmware images")
    parser.add_argument("input", action="store", help="Input file or directory")
    parser.add_argument("output", action="store", nargs="?", default="images",
                        help="Output directory for extracted firmware")
    parser.add_argument("-sql ", dest="sql", action="store", default=None,
                        help="Hostname of SQL server")
    parser.add_argument("-nf", dest="rootfs", action="store_false",
                        default=True, help="Disable extraction of root \
                        filesystem (may decrease extraction time)")
    parser.add_argument("-nk", dest="kernel", action="store_false",
                        default=True, help="Disable extraction of kernel \
                        (may decrease extraction time)")
    parser.add_argument("-np", dest="parallel", action="store_false",
                        default=True, help="Disable parallel operation \
                        (may increase extraction time)")
    parser.add_argument("-b", dest="brand", action="store", default=None,
                        help="Brand of the firmware image")
    parser.add_argument("-d", dest="debug", action="store_true", default=False,
                        help="Print debug information")
    result = parser.parse_args()

    if psql_check(result.sql):
        extract = Extractor(result.input, result.output, result.rootfs,
                            result.kernel, result.parallel, result.sql,
                            result.brand, result.debug)
        extract.extract()

if __name__ == "__main__":
    main()
