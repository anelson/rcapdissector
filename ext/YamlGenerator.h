#pragma once

#include <string>
#include <sstream>
#include <list>

#include "RubyAndShit.h"

/** Native C++ class (not exposed as a Ruby type) that
 *  generates YAML from a Field tree equivalent to using Ruby's
 *  YAML class, but without sucking serious windage.
 *  
 *  http://yaml4r.sourceforge.net/cookbook/ was very helpful
 *  in describing YAML in terms of Ruby */
class YamlGenerator
{

public:
    typedef std::stringstream StringBuffer;

	YamlGenerator(void);
    virtual ~YamlGenerator(void);

    void startList();
    void endList();

    void startMapping(const char* key);
    void startMappingToList(const char* key);
    void endMapping();

    void addMapping(const char* key, const char* value);
    void addMappingWithBinaryValue(const char* key, const guchar* value, size_t length);

    const StringBuffer& getStringBuffer() { return _strBuf;
    }

private:
    /** Internal data structure which stores metadata for each
     *  indent level */
    typedef struct IndentLevel_ {
        bool isList; /** True if this indent level reflects a list of things*/
    } IndentLevel;
    typedef std::list<IndentLevel> IndentLevelStack;

    int _indentLevel;
    StringBuffer _strBuf;
    IndentLevelStack _indentLevels;

    void addIndentLevel(bool isList);
    void removeIndentLevel();

    StringBuffer& startLine();

    void writeBase64StringToBuffer(const guchar* value, size_t length);
    void writeBase64StringChunkToBuffer(char* chunkBuffer, const guchar* value, size_t length);

    static bool needsEscaping(const char* value);
    void writeEscapedString(const char* value);
};
