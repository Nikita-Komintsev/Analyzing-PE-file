import pefile

def main():
    exe_path = "Project1.exe"
    pe = pefile.PE(exe_path)

    # IMAGE_DOS_HEADER
    print("******* DOS_HEADER *******")
    print("e_magic: \t%s" % hex(pe.DOS_HEADER.e_magic))
    print("e_lfanew: \t%s" % hex(pe.DOS_HEADER.e_lfanew))

    # SECTION_HEADERS
    print("\n******* SECTION_HEADERS *******")
    for section in pe.sections:
        print("Section Name:",section.Name.decode('utf-8'))

    # IMAGE_NT_HEADERS
    print("\n******* IMAGE_NT_HEADERS *******")
    print("Signature: %s" % hex(pe.NT_HEADERS.Signature))

    #FILE_HEADER
    print("\n******* IMAGE_FILE_HEADER *******")
    print("Machine:\t\t\t\t\t%s" % hex(pe.FILE_HEADER.Machine))
    print("Number of Sections:\t\t\t%s"% hex(pe.FILE_HEADER.NumberOfSections))
    print("Time Stamp:\t\t\t\t\t%s"% hex(pe.FILE_HEADER.TimeDateStamp))
    print("Size of Optional Header:\t%s" % hex(pe.FILE_HEADER.SizeOfOptionalHeader))
    print("Characteristics:\t\t\t%s" % hex(pe.FILE_HEADER.Characteristics))

    #OPTIONAL_HEADER
    print("\n******* IMAGE_OPTIONAL_HEADER *******")
    print("Magic:\t\t\t\t\t\t\t%s" % hex(pe.OPTIONAL_HEADER.Magic))
    print("Major Linker Version:\t\t\t%s" % hex(pe.OPTIONAL_HEADER.MajorLinkerVersion))
    print("Minor Linker Version:\t\t\t%s" % hex(pe.OPTIONAL_HEADER.MinorLinkerVersion))
    print("Size Of Code:\t\t\t\t\t%s" % hex(pe.OPTIONAL_HEADER.SizeOfCode))
    print("Size Of Initialized Data:\t\t%s" % hex(pe.OPTIONAL_HEADER.SizeOfInitializedData))
    print("Size Of UnInitialized Data:\t\t%s" % hex(pe.OPTIONAL_HEADER.SizeOfUninitializedData))
    print("Address Of Entry Point:\t\t\t%s" % hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    print("Base Of Code:\t\t\t\t\t%s" % hex(pe.OPTIONAL_HEADER.BaseOfCode))
    print("Base Of Data:\t\t\t\t\t%s" % hex(pe.OPTIONAL_HEADER.BaseOfData))
    print("Image Base:\t\t\t\t\t\t%s" % hex(pe.OPTIONAL_HEADER.ImageBase))
    print("Section Alignment:\t\t\t\t%s" % hex(pe.OPTIONAL_HEADER.SectionAlignment))
    print("File Alignment:\t\t\t\t\t%s" % hex(pe.OPTIONAL_HEADER.FileAlignment))
    print("Major Operating System Version:\t%s" % hex(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion))
    print("Minor Operating System Version:\t%s" % hex(pe.OPTIONAL_HEADER.MinorOperatingSystemVersion))
    print("Size Of Image:\t\t\t\t\t%s" % hex(pe.OPTIONAL_HEADER.SizeOfImage))
    print("Size Of Headers:\t\t\t\t%s" % hex(pe.OPTIONAL_HEADER.SizeOfHeaders))
    print("CheckSum:\t\t\t\t\t\t%s" % hex(pe.OPTIONAL_HEADER.CheckSum))
    print("Subsystem:\t\t\t\t\t\t%s" % hex(pe.OPTIONAL_HEADER.Subsystem))
    print("DllCharacteristics:\t\t\t\t%s" % hex(pe.OPTIONAL_HEADER.DllCharacteristics))

    # DATA_DIRECTORIES
    print("\n******* DATA_DIRECTORIES *******")
    print(pe.OPTIONAL_HEADER.DATA_DIRECTORY[0])
    print(pe.OPTIONAL_HEADER.DATA_DIRECTORY[1])

if __name__ == '__main__':
    main()