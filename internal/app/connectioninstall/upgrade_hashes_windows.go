//go:build windows && amd64

package connectioninstall

// Published portable installers that predate automatic upgrade handoff.
var knownUpgradeExecutable = map[string]bool{
	"4f74a3e8c227a69b51e3f12b6869ec6d2ee88ff8f9f23dbb0128456821dcaae2": true, // Verified portable 0.8.28 installer
	"b54eb28132c2b86d7b6bdd62f9f50302da873b03c3fcad6ea14562f28e1a736a": true, // 0.8.29 published exact portable installer
	"035378926ac9c01248df00e1b85739da4d1b0d110da280dca2165d286265e498": true, // 0.8.30 exact published installer
	"8c0451ff8068e87ca58c945f765111b170f699ed936fd0842543b8419e6b7890": true, // Verified portable 0.8.27 installer
	"540211e57bd5ec3a52a38666ba9089f89b25a4f63dedea245403ad76bfb3412a": true, // Verified portable 0.8.26 installer
	"1b56e27c9a58cc7cd842d10ea5b14d1ef4eb8c90f7d7524b1f0737572c255b6d": true, // Verified portable 0.8.25 installer
	"41654adac275d21ac9018c95c363e2a04bae4860731dfa452c3224f17bd0b56f": true, // Verified portable 0.8.24 installer
	"22b22b2b38ed45d14ea032866cbe666802e7a3c1d40e1827d29caeb411a0578c": true, // Verified portable 0.8.23 installer
	"6caf42954a8b3b62d27bd4265ff00299eff7b0b12b76be95ce677095e1757b24": true, // Verified portable 0.8.22 installer
	"895f2a31f1071875e71d8f6744bce5e88cfa21229a5c0c83533208064a3b6dd0": true, // Verified portable 0.8.21 installer
	"f6204925e209069fd24160e812db6589869b6b7d01026b06eedd92fc4326ef8b": true, // 0.8.4
	"7a05dcb40b15104f67fe0abc6e7585211d07fbda2e40b0e4580c5385e74ed116": true, // 0.8.3
	"685cfc12bc66bcf4e97e971f8ab494bd87c4dfea8ea7e4d8fda59a2e6283d31f": true, // 0.8.2
	"24ffe077367375b4c40dffc22ca3e42cb813fea5972756e10e10765f8a0b3e77": true, // 0.8.1
	"e96e175287eaaecc3878e2a8e5b2042d03a8cf7014afe09eb4ac5837bb8b0016": true, // 0.8.0
	"24e0e92e445425f02a57b817544e08c78f56a88033b3011e9d3e1929fb5766f4": true, // 0.7.11
	"73a0871567b9d8f34a4ec22932d0dbb6b05d2a742246f155f85e3e7923290358": true, // 0.7.10
	"bf31737380d137ed146e984faaee2c9433d4edb046a3e0592b497ec991b83859": true, // Suhang-USB-Setup-0.6.0.exe
	"e08774ec98b2d5baa61d021e0b45c3f2682b9f3e3353b9d71194310dda69c950": true, // Suhang-USB-Setup-0.6.1.exe
	"4a217a469918f14b417b598d9c87c57e33ab2f8e7e018bc285202057780ad4c9": true, // Suhang-USB-Setup-0.6.2.exe
	"baccec11196dc1ce58459bb525d8ff383c8ebdb82596d5f160013b540db4c319": true, // Suhang-USB-Setup-0.7.0.exe
	"641b71b4b2349a7a610c38786505b21c4d9aaa05551621a47f98803fc87f6a41": true, // Suhang-USB-Setup-0.7.1.exe
	"8a6f860675c83f1a9ecbbf0e835ffd221c7e4f81e8081104e4c0f82816a8ee50": true, // Suhang-USB-Setup-0.7.2.exe
	"f7dc5724b62b8149d08c38fdaa1f834b9e91878a9af4c9fec037b67f44b44ac7": true, // Suhang-USB-Setup-0.7.3.exe
	"0ed9f7b431d1d30005d692e0115e4d623b536e8b8efe39e01523ba6bd911cd08": true, // Suhang-USB-Setup-0.7.4.exe
	"aca141b176149dea4ead5810b6c7063c03229c491ae88b5afb12f1bf3c8567d7": true, // Suhang-USB-Setup-0.7.5.exe
	"cc322d5509d0ebd97ec6a99273c85447a9c55e1c00f100e87a823b5f77053539": true, // Suhang-USB-Setup-0.7.6.exe
	"d6c217f87d9eba53a6c4ab2862ad818d62be3a53f8cc942cbbe77cad76b9e540": true, // Suhang-USB-Setup-0.7.7.exe
	"bc0f5a59a08c9ed2e251741ba949c635e851f226bad615410f9112c990971cfa": true, // 0.7.9
	"3d8bad2b68da6007785a67100537c3130a837f3836826ac1f582101957ee1dfe": true, // Suhang-USB-Setup-0.7.8.exe
}
