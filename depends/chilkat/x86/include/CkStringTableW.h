// CkStringTableW.h: interface for the CkStringTableW class.
//
//////////////////////////////////////////////////////////////////////

// This header is generated for Chilkat 9.5.0.76

#ifndef _CkStringTableW_H
#define _CkStringTableW_H
	
#include "chilkatDefs.h"

#include "CkString.h"
#include "CkWideCharBase.h"

class CkStringBuilderW;



#if !defined(__sun__) && !defined(__sun)
#pragma pack (push, 8)
#endif
 

// CLASS: CkStringTableW
class CK_VISIBLE_PUBLIC CkStringTableW  : public CkWideCharBase
{
    private:
	

	// Don't allow assignment or copying these objects.
	CkStringTableW(const CkStringTableW &);
	CkStringTableW &operator=(const CkStringTableW &);

    public:
	CkStringTableW(void);
	virtual ~CkStringTableW(void);

	static CkStringTableW *createNew(void);
	

	
	void CK_VISIBLE_PRIVATE inject(void *impl);

	// May be called when finished with the object to free/dispose of any
	// internal resources held by the object. 
	void dispose(void);

	

	// BEGIN PUBLIC INTERFACE

	// ----------------------
	// Properties
	// ----------------------
	// The number of strings in the table.
	int get_Count(void);



	// ----------------------
	// Methods
	// ----------------------
	// Appends a string to the table.
	bool Append(const wchar_t *value);

	// Appends strings, one per line, from a file. Each line in the path should be no
	// longer than the length specified in maxLineLen. The charset indicates the character
	// encoding of the contents of the file, such as "utf-8", "iso-8859-1",
	// "Shift_JIS", etc.
	bool AppendFromFile(int maxLineLen, const wchar_t *charset, const wchar_t *path);

	// Appends strings, one per line, from the contents of a StringBuilder object.
	bool AppendFromSb(CkStringBuilderW &sb);

	// Removes all the strings from the table.
	void Clear(void);

	// Returns the Nth string in the table, converted to an integer value. The index is
	// 0-based. (The first string is at index 0.) Returns -1 if no string is found at
	// the specified index. Returns 0 if the string at the specified index exist, but
	// is not an integer.
	int IntAt(int index);

	// Saves the string table to a file. The charset is the character encoding to use,
	// such as "utf-8", "iso-8859-1", "windows-1252", "Shift_JIS", "gb2312", etc. If
	// bCrlf is true, then CRLF line endings are used, otherwise LF-only line endings
	// are used.
	bool SaveToFile(const wchar_t *charset, bool bCrlf, const wchar_t *path);

	// Splits a string into parts based on a single character delimiterChar. If exceptDoubleQuoted is true,
	// then the delimiter char found between double quotes is not treated as a
	// delimiter. If exceptEscaped is true, then an escaped (with a backslash) delimiter char
	// is not treated as a delimiter.
	bool SplitAndAppend(const wchar_t *inStr, const wchar_t *delimiterChar, bool exceptDoubleQuoted, bool exceptEscaped);

	// Returns the Nth string in the table. The index is 0-based. (The first string is
	// at index 0.)
	bool StringAt(int index, CkString &outStr);
	// Returns the Nth string in the table. The index is 0-based. (The first string is
	// at index 0.)
	const wchar_t *stringAt(int index);





	// END PUBLIC INTERFACE


};
#if !defined(__sun__) && !defined(__sun)
#pragma pack (pop)
#endif


	
#endif