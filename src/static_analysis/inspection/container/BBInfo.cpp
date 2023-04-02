#include "BBInfo.h"

BBInfo::BBInfo(BBId id, const Lines &lineNumbers, const LineRange &lineRange)
    : id(id), lineNumbers(lineNumbers), lineRange(lineRange) {}

BBId BBInfo::getId() const { return id; }

const Lines &BBInfo::getLineNumbers() const { return lineNumbers; }

const LineRange &BBInfo::getLineRange() const { return lineRange; }

bool BBInfo::operator==(const BBInfo &rhs) const {
    return id == rhs.id && lineNumbers == rhs.lineNumbers && lineRange == rhs.lineRange;
}

bool BBInfo::operator!=(const BBInfo &rhs) const { return !(rhs == *this); }
