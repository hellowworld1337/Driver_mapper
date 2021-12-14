#define ToLower(Char) ((Char >= 'A' && Char <= 'Z') ? (Char + 32) : Char)

__forceinline uint64_t Rand() {
	return __rdtsc() * __rdtsc() * __rdtsc();
}

template <typename StrType>
__forceinline int StrLen(StrType Str) {
	if (!Str) return 0;
	StrType Str2 = Str;
	while (*Str2) *Str2++;
	return (int)(Str2 - Str);
}

template <typename StrType, typename StrType2>
__forceinline void StrCpy(StrType Src, StrType2 Dst, wchar_t TNull = 0) {
	if (!Src || !Dst) return;
	while (true) {
		wchar_t WChar = *Dst = *Src++;
		if (WChar == TNull) {
			*Dst = 0; break;
		} Dst++;
	}
}

template <typename StrType, typename StrType2>
__forceinline void StrCat(StrType ToStr, StrType2 Str) {
	StrCpy(Str, (StrType)&ToStr[StrLen(ToStr)]);
}

__forceinline void MemZero(PVOID Dst, DWORD Size) {
	if (!Dst || !Size) return;
	__stosb((PBYTE)Dst, 0, Size);
}

__forceinline void MemCpy(PVOID Dst, PVOID Src, DWORD Size) {
	if (!Dst || !Src || !Size) return;
	__movsb((PBYTE)Dst, (const PBYTE)Src, Size);
}

/*template <typename StrType, typename StrType2>
bool StrStr(StrType Str, StrType2 InStr)
{
	if (!InStr || !Str) return false;
	StrType CurPos = Str; for (int i = 0;; i++) {
		auto CharCur = *CurPos; if (!CharCur) return true;
		auto CharIn = InStr[i]; if (!CharIn) break;
		if (ToLower(CharIn) != ToLower(CharCur))
			CurPos = Str; else CurPos++;
	} return false;
}*/

template <typename StrType, typename StrType2>
__forceinline bool StrCmp(StrType Str, StrType2 InStr, bool Two) {
	if (!Str || !InStr)
		return false;
	wchar_t c1, c2; do {
		c1 = *Str++; c2 = *InStr++;
		c1 = ToLower(c1); c2 = ToLower(c2);
		if (!c1 && (Two ? !c2 : 1)) return true;
	} while (c1 == c2); return false;
}