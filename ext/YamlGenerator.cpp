#include "YamlGenerator.h"

//When dealing with big binary values, base64 encode them one chunk at a time

#define MAX_BINARY_CHUNK_SIZE       4098 //NB: Chunk size needs to be even multiple of 3 so padding won't be added after each chunk

YamlGenerator::YamlGenerator(void) : _indentLevel(0) {
    _strBuf << "---" << std::endl;
}

YamlGenerator::~YamlGenerator(void) {
}

void YamlGenerator::startList() {
    addIndentLevel(true);
}

void YamlGenerator::endList() {
    removeIndentLevel();
}

void YamlGenerator::startMapping(const char* key) {
    startLine() << key << ":" << std::endl;
    addIndentLevel(false);
}

void YamlGenerator::startMappingToList(const char* key) {
    startLine() << key << ":" << std::endl;
    addIndentLevel(true);
}

void YamlGenerator::endMapping() {
    removeIndentLevel();
}

void YamlGenerator::addMapping(const char* key, const char* value) {
    if (!needsEscaping(value)) {
        startLine() << key << ": \"" << value << "\"" << std::endl;
    } else {
        startLine() << key << ": \"";
        writeEscapedString(value);
        _strBuf << "\"" << std::endl;
    }
}

void YamlGenerator::addMappingWithBinaryValue(const char* key, const guchar* value, size_t length) {
    startLine() << key << ": !binary |" << std::endl;

    //Indent the base64-encoded binary value by two more spaces from the key's indent level
    startLine() << "  ";
    writeBase64StringToBuffer(value, length);
    startLine() << "  " << std::endl;
}

void YamlGenerator::addIndentLevel(bool isList) {
    IndentLevel il;
    il.isList = isList;
    _indentLevels.push_back(il);
}

void YamlGenerator::removeIndentLevel() {
    if (_indentLevels.size() > 0) {
        _indentLevels.pop_back();
    } else {
        ::rb_bug("More indent levels removed than added");
    }
}

YamlGenerator::StringBuffer& YamlGenerator::startLine() {
    //Write four spaces for each indent level except skip the indent if the last level if a list
    int i = 0;
    for (IndentLevelStack::const_iterator iter = _indentLevels.begin();
          iter != _indentLevels.end();
          ++iter, ++i) {
        if (iter->isList) {
            //This indent level is a list, so don't generate the four space indent
            continue;
        }
        _strBuf << "    ";
        //_strBuf << i << i << i << i;
    }

    //If the current indent level is a list, prefix the list item indicator
    if (_indentLevels.back().isList) {
        _strBuf << "- ";
    }

    return _strBuf;
}

void YamlGenerator::writeBase64StringToBuffer(const guchar* value, size_t length) {
    char *chunkBuffer = new char[MAX_BINARY_CHUNK_SIZE * 4 / 3 + 6];

    while (length > MAX_BINARY_CHUNK_SIZE) {
        writeBase64StringChunkToBuffer(chunkBuffer, value, MAX_BINARY_CHUNK_SIZE);
        length -= MAX_BINARY_CHUNK_SIZE;
        value += MAX_BINARY_CHUNK_SIZE;
    }

    writeBase64StringChunkToBuffer(chunkBuffer, value, length);

    delete[] chunkBuffer;

    _strBuf << std::endl;
}

/*
 * Built-in base64 (from Ruby's pack.c), stolen in turn from slyc code
 */
static char b64_table[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void YamlGenerator::writeBase64StringChunkToBuffer(char* buff, const guchar* s, size_t len) {
    long i = 0;
    char padding = '=';

    while (len >= 3) {
        buff[i++] = b64_table[077 & (*s >> 2)];
        buff[i++] = b64_table[077 & (((*s << 4) & 060) | ((s[1] >> 4) & 017))];
        buff[i++] = b64_table[077 & (((s[1] << 2) & 074) | ((s[2] >> 6) & 03))];
        buff[i++] = b64_table[077 & s[2]];
        s += 3;
        len -= 3;
    }
    if (len == 2) {
        buff[i++] = b64_table[077 & (*s >> 2)];
        buff[i++] = b64_table[077 & (((*s << 4) & 060) | ((s[1] >> 4) & 017))];
        buff[i++] = b64_table[077 & (((s[1] << 2) & 074) | (('\0' >> 6) & 03))];
        buff[i++] = padding;
    }
    else if (len == 1) {
        buff[i++] = b64_table[077 & (*s >> 2)];
        buff[i++] = b64_table[077 & (((*s << 4) & 060) | (('\0' >> 4) & 017))];
        buff[i++] = padding;
        buff[i++] = padding;
    }
    buff[i] = '\0';

    _strBuf << buff;
}

bool YamlGenerator::needsEscaping(const char* value) {
    //Look for strings that need escaping
    return 
        ::strstr(value, "\"") != NULL ||
        ::strstr(value, "\\") != NULL;
}


void YamlGenerator::writeEscapedString(const char* value) {
    //Replace each instance of a character requiring escaping with the escaped character
    //TODO: This could be optimized alot more 
    std::string str = value;
	size_t idx;

    //Escape the backslashes
    idx = 0;
    while ((idx = str.find('\\', idx)) != std::string::npos) {
		//::rb_warn("Found backslash at index %d in '%s'", idx, str.c_str());

        str.erase(idx, 1);
        str.insert(idx, "\\\\");

		//::rb_warn("Escaped backslash at index %d in '%s'", idx, str.c_str());
        idx += 2;
    }

    //Escape the quotes
    idx = 0;
	while ((idx = str.find('\"', idx)) != std::string::npos) {
		//::rb_warn("Found quote at index %d in '%s'", idx, str.c_str());

        str.erase(idx, 1);
        str.insert(idx, "\\\"");

		//::rb_warn("Escaped quote at index %d in '%s'", idx, str.c_str());
        idx += 2;
    }

    _strBuf << str;
}
