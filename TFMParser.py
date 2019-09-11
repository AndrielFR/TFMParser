import glob
import os
import time

class TFMParser():
    def __init__(self):
        self.directory = ""
        self.connectionKey = ""
        self.ip = ""

        self.version = 0

        self.files = []
        self.ports = []
        self.loginKeys = []

    def start(self):
        self.searchFolders()
        print("Searching...")
        self.searchIP()
        self.searchPorts()
        self.searchVersion()
        self.searchConnectionKey()

    def searchFolders(self):
        fd = [f for f in os.listdir() if not os.path.isfile(f) and "-" in f]
        if len(fd) == 1:
            print("Only "+str(fd[0])+" found")
            cn = input("Type 'y' to use the folder '"+str(fd[0])+"' or 'n' to enter the directory of the desired folder: ")
            if cn == "y":
                self.directory = fd[0]+"/{0}.class.asasm"
            else:
                self.directory = input("Enter the desired directory: ")+"/{0}.class.asasm"
                print("The desired directory is: "+str(self.directory))
        else:
            i = 0
            for f in fd:
                print(str(f)+" ["+str(i)+"]")
                i += 1
            n = input("Select the folder number: ")
            self.directory = fd[int(n)]+"/{0}.class.asasm"
        print("Collecting files...")
        for asasm in glob.glob(self.directory.format("*")):
            self.files += [asasm]

    def searchIP(self):
        for f in self.files:
            l = self.rLines(f)
            i = 0
            while i < len(l):
                if 'findpropstrict' in l[i-1]:
                    if 'pushfalse' in l[i+1]:
                        if 'pushstring' in l[i]:
                            self.ip = l[i].split('"')[1].split('"')[0].split(':')[0]
                i += 1
        print("IP: ["+str(self.ip)+"]")

    def searchPorts(self):
        for f in self.files:
            l = self.rLines(f)
            i = 0
            while i < len(l):
                if 'findpropstrict' in l[i-1]:
                    if 'pushfalse' in l[i+1]:
                        if 'pushstring' in l[i]:
                            self.ports = [int(p) for p in l[i].split('"')[1].split('"')[0].split(':')[1].split('-')]
                i += 1
        print("Ports: "+str(self.ports))

    def searchVersion(self):
        for f in self.files:
            l = self.rLines(f)
            i = 0
            while i < len(l):
                if not 'end ; code' in l[i-3] and 'end ; body' in l[i-2]:
                    if 'type QName(PackageNamespace(""), "int") value Double' in l[i]:
                        if 'type QName(PackageNamespace(""), "int") value Double' in l[i+1]:
                            v = int(l[i].split("Double(")[-1].split(")")[0])
                            if v < 700:
                                self.version = v
                i += 1
        print("Version: [1."+str(self.version)+"]")

    def searchConnectionKey(self):
        ck = []
        glex = []
        gproperty = []
        for f in self.files:
            l = self.rLines(f)
            i = 0
            while i < len(l):
                if 'SHA256_faux' in l[i]:
                    if 'getlex' in l[i+6]:
                        x = i
                        while not 'getlex              QName(PackageNamespace("flash.system"), "Capabilities")' in l[x]:
                            if 'getlex' in l[x]:
                                if 'getproperty' in l[x+1] and not 'findpropstrict' in l[x+2]:
                                    glex.append(l[x].split('"')[-2].split('"')[0].replace("\\x", "%"))
                                    gproperty.append(l[x+1].split('"')[-2].split('"')[0])
                            x += 1
                i += 1
        p = 0
        for f in glex:
            l = self.rLines(f, True)
            i = 0
            while i < len(l):
                if gproperty[p] in l[i-1]:
                    if 'pushstring' in l[i]:
                        self.connectionKey += l[i].split('"')[1].split('"')[0]
                        p += 1
                        break
                i += 1
        print('Connection Key: ["'+str(self.connectionKey)+'"]')

    def rFile(self, file, isClass=False):
        f = file.replace("\\x", "%")
        if isClass:f = self.directory.format(f)
        r = open(f, "r+", encoding='utf8')
        t = r.read()
        r.close()
        return t

    def rLines(self, file, isClass=False):
        return self.rFile(file, isClass).split('\n')

    def wFile(self, file, content, isClass=False):
        f = file.replace("\\x", "%")
        if isClass:f = self.directory.format(f)
        w = os.open(f, "w+")
        w.write(str(content))
        w.close()

if __name__ == "__main__":
    os.system("title TFMParser v0.1")
    try:
        TFMParser().start()
    except Exception as e:
        print(e)
    time.sleep(10)