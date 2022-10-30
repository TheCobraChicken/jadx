package jadx.core.libgen;


import jadx.api.ResourcesLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jadx.api.ICodeInfo;
import jadx.api.ICodeWriter;
import jadx.api.ICodeInfo;
import jadx.core.dex.info.ConstStorage;
import jadx.core.dex.nodes.RootNode;
import jadx.core.utils.exceptions.JadxRuntimeException;
import jadx.core.xmlgen.ParserStream;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import java.util.Map;

public class ElfParser {
	private static final Logger LOG = LoggerFactory.getLogger(ElfParser.class);

	private final Map<Integer, String> resNames;
	private final RootNode rootNode;
	private ICodeWriter writer;
	protected ParserStream is;

	//file header
	private int eiBitFormat;
	private int eiEndian;
	private int eiVersion;
	private int eiOsabi;
	private int eiAbiVersion;
	private int eType;
	private int eMachine;
	private int eVersion;
	private long eEntry;
	private long ePhoff;
	private long eShoff;
	private int eFlags;
	private int eEhsize;
	private int ePhentsize;
	private int ePhnum;
	private int eShentsize;
	private int eShnum;
	private int eShstrndx;

	//program header
	private int pType;
	private int pFlags;
	private long pOffset;
	private long pVaddr;
	private long pPaddr;
	private long pFilesz;
	private long pMemsz;
	private long pAlign;

	//section header
	private int shName;
	private int shType;
	private long shAddr;
	private long shFlag;
	private long shOffset;
	private long shSize;
	private long shLink;
	private long shInfo;
	private long shAddralign;
	private long shEntsize;

	public ElfParser(RootNode rootNode) {
		this.rootNode = rootNode;
		try {
			ConstStorage constStorage = rootNode.getConstValues();
			resNames = constStorage.getResourcesNames();
		} catch (Exception e) {
			throw new JadxRuntimeException("ElfParser init error", e);
		}
	}

	private boolean isElf() throws IOException {
		is.mark(4);
		int m = is.readInt32(); // magic bytes "0x7FELF"
		if (m == 0x7F454C46) {
			return true;
		}
		is.reset();
		return false;
	}

	private void readHeader() throws IOException {
		eiBitFormat = is.readInt8();
		eiEndian = is.readInt8();
		eiVersion = is.readInt8();
		eiOsabi = is.readInt8();
		eiAbiVersion = is.readInt8();
		is.skip(7); // skipping padding
		if(eiEndian == 1) {
			is.setEndian(true);
		}
		eType = is.readInt16();
		eMachine = is.readInt16();
		eVersion = is.readInt32();

		if(eiBitFormat == 1) {
			eEntry = is.readInt32();
			ePhoff = is.readInt32();
			eShoff = is.readInt32();
		} else if(eiBitFormat == 2) {
			eEntry = is.readLong64();
			ePhoff = is.readLong64();
			eShoff = is.readLong64();
		}

		eFlags = is.readInt32();
		eEhsize = is.readInt16();
		ePhentsize = is.readInt16();
		ePhnum = is.readInt16();
		eShentsize = is.readInt16();
		eShnum = is.readInt16();
		eShstrndx = is.readInt16();

		writer.add("### Header ###");
		writer.startLine("CLASS - 1 == 32 bit, 2 == 64 bit:\t" + eiBitFormat);
		writer.startLine("ENDIAN - 1 == little:\t" + eiEndian);
		writer.startLine("EI VERSION:\t" + eiVersion);
		writer.startLine("OSABI - Operating System Image:\t" + eiOsabi);
		writer.startLine("ABIVERSION - Further Specify OS Version:\t" + eiAbiVersion);
		writer.startLine("TYPE - Object Type:\t" + eType);
		writer.startLine("MACHINE - Architecture:\t" + eMachine);
		writer.startLine("VERSION:\t" + eVersion);
		writer.startLine("ENTRY - Address of Execute Entry:\t" + eEntry);
		writer.startLine("PHOFF - Address Program Header:\t" + ePhoff);
		writer.startLine("SHOFF - Address of Section Header:\t" + eShoff);
		writer.startLine("FLAGS:\t" + eFlags);
		writer.startLine("EHSIZE - File Header Size:\t" + eEhsize);
		writer.startLine("PHENTSIZE - Program Header Entry Size:\t" + ePhentsize);
		writer.startLine("PHNUM - Entries in Program Header:\t" + ePhnum);
		writer.startLine("SHENTSIZE - Section Header Size:\t" + eShentsize);
		writer.startLine("SHNUM - Entries in Section Header:\t" + eShnum);
		writer.startLine("SHSTRNDX - Section Name Index:\t" + eShstrndx);
		writer.startLine();
	}

	private void readProgramHeader() throws IOException {
		is.reset();
		is.skip(ePhoff); // skipping to program offset
		for(int i = 0; i < ePhnum; i++) {
			pType = is.readInt32();
			if (eiBitFormat == 1) {
				pOffset = is.readInt32();
				pVaddr = is.readInt32();
				pPaddr = is.readInt32();
				pFilesz = is.readInt32();
				pMemsz = is.readInt32();
				pFlags = is.readInt32();
				pAlign = is.readInt32();
			} else if (eiBitFormat == 2) {
				pFlags = is.readInt32();
				pOffset = is.readLong64();
				pVaddr = is.readLong64();
				pPaddr = is.readLong64();
				pFilesz = is.readLong64();
				pMemsz = is.readLong64();
				pAlign = is.readLong64();
			}

			writer.startLine("### Program Header ###");
			writer.startLine("PTYPE - Segment TYPE:\t" + pType);
			writer.startLine("PFLAGS - Segment FLAGS:\t" + pFlags);
			writer.startLine("POFFSET - Segment OFFSET:\t" + pOffset);
			writer.startLine("PVADDR - Segment Virtual Address:\t" + pVaddr);
			writer.startLine("PPADDR - Segment Physical Address:\t" + pPaddr);
			writer.startLine("FILESZ - Segment Size in File Image:\t" + pFilesz);
			writer.startLine("MEMSZ - Sigment Size in Memory:\t" + pMemsz);
			writer.startLine("ALIGN:\t" + pAlign);
			writer.startLine();
		}
	}

	private void readSectionHeader() throws IOException {
		is.reset();
		is.skip(eShoff); // skipping to section offset
		for(int i = 0; i < eShnum; i++) {
			shName = is.readInt32();
			shType = is.readInt32();
			if (eiBitFormat == 1) {
				shFlag = is.readInt32();
				shAddr = is.readInt32();
				shOffset = is.readInt32();
				shSize = is.readInt32();
				shLink = is.readInt32();
				shInfo = is.readInt32();
				shAddralign = is.readInt32();
				shEntsize = is.readInt32();
			} else if (eiBitFormat == 2) {
				shFlag = is.readLong64();
				shAddr = is.readLong64();
				shOffset = is.readLong64();
				shSize = is.readLong64();
				shLink = is.readInt32();
				shInfo = is.readInt32();
				shAddralign = is.readLong64();
				shEntsize = is.readLong64();
			}
			writer.startLine("### Section Header ###");
			writer.startLine("NAME - Offset to .shstrtab:\t" + shName);
			writer.startLine("TYPE:\t" + shType);
			writer.startLine("FLAG - Section Attributes:\t" + shFlag);
			writer.startLine("ADDR - Section Virtual Address in Memory:\t" + shAddr);
			writer.startLine("OFFSET - Section File Image Offset:\t" + shOffset);
			writer.startLine("SIZE - Section Size:\t" + shSize);
			writer.startLine("LINK - Associated Section Index:\t" + shLink);
			writer.startLine("INFO - Extra Info:\t" + shInfo);
			writer.startLine("ADDRALIGN - Alignment of Section:\t" + shAddralign);
			writer.startLine("ENTSIZE - For Fixed-Size Sections contains size:\t" + shEntsize);
			writer.startLine();
		}
	}

	private void decode() throws IOException {
		readHeader();
		readProgramHeader();
		readSectionHeader();
	}

	public synchronized ICodeInfo parse(InputStream inputStream) throws IOException {
		is = new ParserStream(inputStream, false);
		if(!isElf()) {
			return ResourcesLoader.loadToCodeWriter(new ByteArrayInputStream("Error: Invalid ELF File".getBytes()));
		}

		writer = rootNode.makeCodeWriter();
		decode();

		ICodeInfo codeInfo = writer.finish();
		return codeInfo;
	}
}
