static const char *input[] = {
	"SSdtIHJhdGVkICJSIi4uLnRoaXMgaXMgYSB3YXJuaW5nLCB5YSBiZXR0ZXIgdm9pZCAvIF"
		"BvZXRzIGFyZSBwYXJhbm9pZCwgREoncyBELXN0cm95ZWQ=",
	"Q3V6IEkgY2FtZSBiYWNrIHRvIGF0dGFjayBvdGhlcnMgaW4gc3BpdGUtIC8gU3RyaWtlIG"
		"xpa2UgbGlnaHRuaW4nLCBJdCdzIHF1aXRlIGZyaWdodGVuaW4nIQ==",
	"QnV0IGRvbid0IGJlIGFmcmFpZCBpbiB0aGUgZGFyaywgaW4gYSBwYXJrIC8gTm90IGEgc2"
		"NyZWFtIG9yIGEgY3J5LCBvciBhIGJhcmssIG1vcmUgbGlrZSBhIHNw"
		"YXJrOw==",
	"WWEgdHJlbWJsZSBsaWtlIGEgYWxjb2hvbGljLCBtdXNjbGVzIHRpZ2h0ZW4gdXAgLyBXaG"
		"F0J3MgdGhhdCwgbGlnaHRlbiB1cCEgWW91IHNlZSBhIHNpZ2h0IGJ1"
		"dA==",
	"U3VkZGVubHkgeW91IGZlZWwgbGlrZSB5b3VyIGluIGEgaG9ycm9yIGZsaWNrIC8gWW91IG"
		"dyYWIgeW91ciBoZWFydCB0aGVuIHdpc2ggZm9yIHRvbW9ycm93IHF1"
		"aWNrIQ==",
	"TXVzaWMncyB0aGUgY2x1ZSwgd2hlbiBJIGNvbWUgeW91ciB3YXJuZWQgLyBBcG9jYWx5cH"
		"NlIE5vdywgd2hlbiBJJ20gZG9uZSwgeWEgZ29uZSE=",
	"SGF2ZW4ndCB5b3UgZXZlciBoZWFyZCBvZiBhIE1DLW11cmRlcmVyPyAvIFRoaXMgaXMgdG"
		"hlIGRlYXRoIHBlbmFsdHksYW5kIEknbSBzZXJ2aW4nIGE=",
	"RGVhdGggd2lzaCwgc28gY29tZSBvbiwgc3RlcCB0byB0aGlzIC8gSHlzdGVyaWNhbCBpZG"
		"VhIGZvciBhIGx5cmljYWwgcHJvZmVzc2lvbmlzdCE=",
	"RnJpZGF5IHRoZSB0aGlydGVlbnRoLCB3YWxraW5nIGRvd24gRWxtIFN0cmVldCAvIFlvdS"
		"Bjb21lIGluIG15IHJlYWxtIHlhIGdldCBiZWF0IQ==",
	"VGhpcyBpcyBvZmYgbGltaXRzLCBzbyB5b3VyIHZpc2lvbnMgYXJlIGJsdXJyeSAvIEFsbC"
		"B5YSBzZWUgaXMgdGhlIG1ldGVycyBhdCBhIHZvbHVtZQ==",
	"VGVycm9yIGluIHRoZSBzdHlsZXMsIG5ldmVyIGVycm9yLWZpbGVzIC8gSW5kZWVkIEknbS"
		"Brbm93bi15b3VyIGV4aWxlZCE=",
	"Rm9yIHRob3NlIHRoYXQgb3Bwb3NlIHRvIGJlIGxldmVsIG9yIG5leHQgdG8gdGhpcyAvIE"
		"kgYWluJ3QgYSBkZXZpbCBhbmQgdGhpcyBhaW4ndCB0aGUgRXhvcmNp"
		"c3Qh",
	"V29yc2UgdGhhbiBhIG5pZ2h0bWFyZSwgeW91IGRvbid0IGhhdmUgdG8gc2xlZXAgYSB3aW"
		"5rIC8gVGhlIHBhaW4ncyBhIG1pZ3JhaW5lIGV2ZXJ5IHRpbWUgeWEg"
		"dGhpbms=",
	"Rmxhc2hiYWNrcyBpbnRlcmZlcmUsIHlhIHN0YXJ0IHRvIGhlYXI6IC8gVGhlIFItQS1LLU"
		"ktTSBpbiB5b3VyIGVhcjs=",
	"VGhlbiB0aGUgYmVhdCBpcyBoeXN0ZXJpY2FsIC8gVGhhdCBtYWtlcyBFcmljIGdvIGdldC"
		"BhIGF4IGFuZCBjaG9wcyB0aGUgd2Fjaw==",
	"U29vbiB0aGUgbHlyaWNhbCBmb3JtYXQgaXMgc3VwZXJpb3IgLyBGYWNlcyBvZiBkZWF0aC"
		"ByZW1haW4=",
	"TUMncyBkZWNheWluZywgY3V6IHRoZXkgbmV2ZXIgc3RheWVkIC8gVGhlIHNjZW5lIG9mIG"
		"EgY3JpbWUgZXZlcnkgbmlnaHQgYXQgdGhlIHNob3c=",
	"VGhlIGZpZW5kIG9mIGEgcmh5bWUgb24gdGhlIG1pYyB0aGF0IHlvdSBrbm93IC8gSXQncy"
		"Bvbmx5IG9uZSBjYXBhYmxlLCBicmVha3MtdGhlIHVuYnJlYWthYmxl",
	"TWVsb2RpZXMtdW5tYWthYmxlLCBwYXR0ZXJuLXVuZXNjYXBhYmxlIC8gQSBob3JuIGlmIH"
		"dhbnQgdGhlIHN0eWxlIEkgcG9zc2Vz",
	"SSBibGVzcyB0aGUgY2hpbGQsIHRoZSBlYXJ0aCwgdGhlIGdvZHMgYW5kIGJvbWIgdGhlIH"
		"Jlc3QgLyBGb3IgdGhvc2UgdGhhdCBlbnZ5IGEgTUMgaXQgY2FuIGJl",
	"SGF6YXJkb3VzIHRvIHlvdXIgaGVhbHRoIHNvIGJlIGZyaWVuZGx5IC8gQSBtYXR0ZXIgb2"
		"YgbGlmZSBhbmQgZGVhdGgsIGp1c3QgbGlrZSBhIGV0Y2gtYS1za2V0"
		"Y2g=",
	"U2hha2UgJ3RpbGwgeW91ciBjbGVhciwgbWFrZSBpdCBkaXNhcHBlYXIsIG1ha2UgdGhlIG"
		"5leHQgLyBBZnRlciB0aGUgY2VyZW1vbnksIGxldCB0aGUgcmh5bWUg"
		"cmVzdCBpbiBwZWFjZQ==",
	"SWYgbm90LCBteSBzb3VsJ2xsIHJlbGVhc2UhIC8gVGhlIHNjZW5lIGlzIHJlY3JlYXRlZC"
		"wgcmVpbmNhcm5hdGVkLCB1cGRhdGVkLCBJJ20gZ2xhZCB5b3UgbWFk"
		"ZSBpdA==",
	"Q3V6IHlvdXIgYWJvdXQgdG8gc2VlIGEgZGlzYXN0cm91cyBzaWdodCAvIEEgcGVyZm9ybW"
		"FuY2UgbmV2ZXIgYWdhaW4gcGVyZm9ybWVkIG9uIGEgbWljOg==",
	"THlyaWNzIG9mIGZ1cnkhIEEgZmVhcmlmaWVkIGZyZWVzdHlsZSEgLyBUaGUgIlIiIGlzIG"
		"luIHRoZSBob3VzZS10b28gbXVjaCB0ZW5zaW9uIQ==",
	"TWFrZSBzdXJlIHRoZSBzeXN0ZW0ncyBsb3VkIHdoZW4gSSBtZW50aW9uIC8gUGhyYXNlcy"
		"B0aGF0J3MgZmVhcnNvbWU=",
	"WW91IHdhbnQgdG8gaGVhciBzb21lIHNvdW5kcyB0aGF0IG5vdCBvbmx5IHBvdW5kcyBidX"
		"QgcGxlYXNlIHlvdXIgZWFyZHJ1bXM7IC8gSSBzaXQgYmFjayBhbmQg"
		"b2JzZXJ2ZSB0aGUgd2hvbGUgc2NlbmVyeQ==",
	"VGhlbiBub25jaGFsYW50bHkgdGVsbCB5b3Ugd2hhdCBpdCBtZWFuIHRvIG1lIC8gU3RyaW"
		"N0bHkgYnVzaW5lc3MgSSdtIHF1aWNrbHkgaW4gdGhpcyBtb29k",
	"QW5kIEkgZG9uJ3QgY2FyZSBpZiB0aGUgd2hvbGUgY3Jvd2QncyBhIHdpdG5lc3MhIC8gSS"
		"dtIGEgdGVhciB5b3UgYXBhcnQgYnV0IEknbSBhIHNwYXJlIHlvdSBh"
		"IGhlYXJ0",
	"UHJvZ3JhbSBpbnRvIHRoZSBzcGVlZCBvZiB0aGUgcmh5bWUsIHByZXBhcmUgdG8gc3Rhcn"
		"QgLyBSaHl0aG0ncyBvdXQgb2YgdGhlIHJhZGl1cywgaW5zYW5lIGFz"
		"IHRoZSBjcmF6aWVzdA==",
	"TXVzaWNhbCBtYWRuZXNzIE1DIGV2ZXIgbWFkZSwgc2VlIGl0J3MgLyBOb3cgYW4gZW1lcm"
		"dlbmN5LCBvcGVuLWhlYXJ0IHN1cmdlcnk=",
	"T3BlbiB5b3VyIG1pbmQsIHlvdSB3aWxsIGZpbmQgZXZlcnkgd29yZCdsbCBiZSAvIEZ1cm"
		"llciB0aGFuIGV2ZXIsIEkgcmVtYWluIHRoZSBmdXJ0dXJl",
	"QmF0dGxlJ3MgdGVtcHRpbmcuLi53aGF0ZXZlciBzdWl0cyB5YSEgLyBGb3Igd29yZHMgdG"
		"hlIHNlbnRlbmNlLCB0aGVyZSdzIG5vIHJlc2VtYmxhbmNl",
	"WW91IHRoaW5rIHlvdSdyZSBydWZmZXIsIHRoZW4gc3VmZmVyIHRoZSBjb25zZXF1ZW5jZX"
		"MhIC8gSSdtIG5ldmVyIGR5aW5nLXRlcnJpZnlpbmcgcmVzdWx0cw==",
	"SSB3YWtlIHlhIHdpdGggaHVuZHJlZHMgb2YgdGhvdXNhbmRzIG9mIHZvbHRzIC8gTWljLX"
		"RvLW1vdXRoIHJlc3VzY2l0YXRpb24sIHJoeXRobSB3aXRoIHJhZGlh"
		"dGlvbg==",
	"Tm92b2NhaW4gZWFzZSB0aGUgcGFpbiBpdCBtaWdodCBzYXZlIGhpbSAvIElmIG5vdCwgRX"
		"JpYyBCLidzIHRoZSBqdWRnZSwgdGhlIGNyb3dkJ3MgdGhlIGp1cnk=",
	"WW8gUmFraW0sIHdoYXQncyB1cD8gLyBZbywgSSdtIGRvaW5nIHRoZSBrbm93bGVkZ2UsIE"
		"UuLCBtYW4gSSdtIHRyeWluZyB0byBnZXQgcGFpZCBpbiBmdWxs",
	"V2VsbCwgY2hlY2sgdGhpcyBvdXQsIHNpbmNlIE5vcmJ5IFdhbHRlcnMgaXMgb3VyIGFnZW"
		"5jeSwgcmlnaHQ/IC8gVHJ1ZQ==",
	"S2FyYSBMZXdpcyBpcyBvdXIgYWdlbnQsIHdvcmQgdXAgLyBaYWtpYSBhbmQgNHRoIGFuZC"
		"BCcm9hZHdheSBpcyBvdXIgcmVjb3JkIGNvbXBhbnksIGluZGVlZA==",
	"T2theSwgc28gd2hvIHdlIHJvbGxpbicgd2l0aCB0aGVuPyBXZSByb2xsaW4nIHdpdGggUn"
		"VzaCAvIE9mIFJ1c2h0b3duIE1hbmFnZW1lbnQ=",
	"Q2hlY2sgdGhpcyBvdXQsIHNpbmNlIHdlIHRhbGtpbmcgb3ZlciAvIFRoaXMgZGVmIGJlYX"
		"QgcmlnaHQgaGVyZSB0aGF0IEkgcHV0IHRvZ2V0aGVy",
	"SSB3YW5uYSBoZWFyIHNvbWUgb2YgdGhlbSBkZWYgcmh5bWVzLCB5b3Uga25vdyB3aGF0IE"
		"knbSBzYXlpbic/IC8gQW5kIHRvZ2V0aGVyLCB3ZSBjYW4gZ2V0IHBh"
		"aWQgaW4gZnVsbA==",
	"VGhpbmtpbicgb2YgYSBtYXN0ZXIgcGxhbiAvICdDdXogYWluJ3QgbnV0aGluJyBidXQgc3"
		"dlYXQgaW5zaWRlIG15IGhhbmQ=",
	"U28gSSBkaWcgaW50byBteSBwb2NrZXQsIGFsbCBteSBtb25leSBpcyBzcGVudCAvIFNvIE"
		"kgZGlnIGRlZXBlciBidXQgc3RpbGwgY29taW4nIHVwIHdpdGggbGlu"
		"dA==",
	"U28gSSBzdGFydCBteSBtaXNzaW9uLCBsZWF2ZSBteSByZXNpZGVuY2UgLyBUaGlua2luJy"
		"Bob3cgY291bGQgSSBnZXQgc29tZSBkZWFkIHByZXNpZGVudHM=",
	"SSBuZWVkIG1vbmV5LCBJIHVzZWQgdG8gYmUgYSBzdGljay11cCBraWQgLyBTbyBJIHRoaW"
		"5rIG9mIGFsbCB0aGUgZGV2aW91cyB0aGluZ3MgSSBkaWQ=",
	"SSB1c2VkIHRvIHJvbGwgdXAsIHRoaXMgaXMgYSBob2xkIHVwLCBhaW4ndCBudXRoaW4nIG"
		"Z1bm55IC8gU3RvcCBzbWlsaW5nLCBiZSBzdGlsbCwgZG9uJ3QgbnV0"
		"aGluJyBtb3ZlIGJ1dCB0aGUgbW9uZXk=",
	"QnV0IG5vdyBJIGxlYXJuZWQgdG8gZWFybiAnY3V6IEknbSByaWdodGVvdXMgLyBJIGZlZW"
		"wgZ3JlYXQsIHNvIG1heWJlIEkgbWlnaHQganVzdA==",
	"U2VhcmNoIGZvciBhIG5pbmUgdG8gZml2ZSwgaWYgSSBzdHJpdmUgLyBUaGVuIG1heWJlIE"
		"knbGwgc3RheSBhbGl2ZQ==",
	"U28gSSB3YWxrIHVwIHRoZSBzdHJlZXQgd2hpc3RsaW4nIHRoaXMgLyBGZWVsaW4nIG91dC"
		"BvZiBwbGFjZSAnY3V6LCBtYW4sIGRvIEkgbWlzcw==",
	"QSBwZW4gYW5kIGEgcGFwZXIsIGEgc3RlcmVvLCBhIHRhcGUgb2YgLyBNZSBhbmQgRXJpYy"
		"BCLCBhbmQgYSBuaWNlIGJpZyBwbGF0ZSBvZg==",
	"RmlzaCwgd2hpY2ggaXMgbXkgZmF2b3JpdGUgZGlzaCAvIEJ1dCB3aXRob3V0IG5vIG1vbm"
		"V5IGl0J3Mgc3RpbGwgYSB3aXNo",
	"J0N1eiBJIGRvbid0IGxpa2UgdG8gZHJlYW0gYWJvdXQgZ2V0dGluJyBwYWlkIC8gU28gSS"
		"BkaWcgaW50byB0aGUgYm9va3Mgb2YgdGhlIHJoeW1lcyB0aGF0IEkg"
		"bWFkZQ==",
	"U28gbm93IHRvIHRlc3QgdG8gc2VlIGlmIEkgZ290IHB1bGwgLyBIaXQgdGhlIHN0dWRpby"
		"wgJ2N1eiBJJ20gcGFpZCBpbiBmdWxs",
	"UmFraW0sIGNoZWNrIHRoaXMgb3V0LCB5byAvIFlvdSBnbyB0byB5b3VyIGdpcmwgaG91c2"
		"UgYW5kIEknbGwgZ28gdG8gbWluZQ==",
	"J0NhdXNlIG15IGdpcmwgaXMgZGVmaW5pdGVseSBtYWQgLyAnQ2F1c2UgaXQgdG9vayB1cy"
		"B0b28gbG9uZyB0byBkbyB0aGlzIGFsYnVt",
	"WW8sIEkgaGVhciB3aGF0IHlvdSdyZSBzYXlpbmcgLyBTbyBsZXQncyBqdXN0IHB1bXAgdG"
		"hlIG11c2ljIHVw",
	"QW5kIGNvdW50IG91ciBtb25leSAvIFlvLCB3ZWxsIGNoZWNrIHRoaXMgb3V0LCB5byBFbG"
		"k=",
	"VHVybiBkb3duIHRoZSBiYXNzIGRvd24gLyBBbmQgbGV0IHRoZSBiZWF0IGp1c3Qga2VlcC"
		"BvbiByb2NraW4n",
	"QW5kIHdlIG91dHRhIGhlcmUgLyBZbywgd2hhdCBoYXBwZW5lZCB0byBwZWFjZT8gLyBQZW"
		"FjZQ==",
};
