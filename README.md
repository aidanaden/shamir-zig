# shamir-secret-sharing

Simple zig implementation of [Shamir's Secret Sharing algorithm](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing).

2 implementations exist:

1. Uses GF(2^8). Implementation inspired by [privy-io/shamir-secret-sharing](https://github.com/privy-io/shamir-secret-sharing) and [hashicorp/vault](https://github.com/hashicorp/vault/tree/main/shamir).

2. Uses Ristretto255. Implementation inspired by [coinbase/kryptology](https://github.com/coinbase/kryptology)

Includes a CLI app for independent use of shamir secret sharing.

## Security considerations

1. Although the reference implementations have been audited, this implementation was NOT audited and was written for FUN. DO NOT USE THIS IN PRODUCTION.
2. This library is not responsible for verifying the result of share reconstruction. Incorrect or corrupted shares will produce an incorrect value. Thus, it is the responsibility of users of this library to verify the integrity of the reconstructed secret.
3. Secrets should ideally be uniformly distributed at random. If this is not the case, it is recommended to first encrypt the value and split the encryption key.

## Importing

1. Run the following command:

```
zig fetch --save git+https://github.com/aidanaden/shamir-zig
```

2. Add the following to `build.zig`:

```zig
const shamir = b.dependency("shamir-zig", .{});
exe.root_module.addImport("shamir", shamir.module("shamir"));
```

## Installation

### Nix

```sh
nix run github:aidanaden/shamir-zig
```

### Brew

```sh
brew install aidanaden/tools/shamir
```

## Usage

We can `generate` shares from a given secret and later `reconstruct` the secret from the minimum number of shares (as configured when running `generate`).

Note: for algorithms using Ed25519, the secret is hashed via Sha512 and reduced into a value (32-bytes) within the Ed25519 curve. Reduction is required since the secret can only be reconstructed as a value within the Ed25519 curve.

### CLI

#### Shamir GF256

```sh
./zig-out/bin/shamir generate --threshold 4 --total 10 --secret mynamejeff
# --- output ---
#
# secret (hex): 6D796E616D656A656666
#
# shares (4/10 required):
# C55F6C84575C6B4BB0B639
# F464701E29B79D09483736
# 34345F1C0918C6DC1A593D
# 3185D736294DAC48D85F8C
# E392144022D14FCB9DF202
# A87636B60C88A103561E29
# 9E1C2F10E1AFAE3E7732BC
# DF3C164FFD60A0B4DB3A91
# 253DC1AFC299E1D63AAFD2
# AF08A0E9F9362F13775FFA
```

```sh
./zig-out/bin/shamir reconstruct -s=34345F1C0918C6DC1A593D,253DC1AFC299E1D63AAFD2,AF08A0E9F9362F13775FFA,C55F6C84575C6B4BB0B639
# --- output ---
# secret (hex): 6D796E616D656A656666
# secret (text): mynamejeff
```

#### Shamir Ed25519 via Ristretto255

```sh
./zig-out/bin/shamir generate --threshold 4 --total 10 --secret mynamejeff -m s25519
# --- output ---
#
# secret (hashed): 6D33F29E352F4A76FB61C06E6AC84163760FE73CBDEEA718B366DB62EB0EAAA9
# secret (hashed + reduced): 2BEC57FD2D5092059C411411B8058C92750FE73CBDEEA718B366DB62EB0EAA09
#
# shares (4/10 required):
# 13EA9709CC727E0CA9318D88952857DC09C4623D4BECFA80BB4A11BC3590D90F95A112BB916F7310A1096D8BBFD8F2CE8510DB466591B5C30F5D7C6709BD0C0B
# A2B0D0804BC85A78FB823D5F0EAC6D1BEE33B571B8B6CFD092256D335527DE052420E113ECA01ED66548E3B3C7DE9E63CF1B577198F2FE1359F36510C372830C
# 98EAF99A5C2C9DF845C1B60B6BCC98BED71C32D0DD234124F5589ECD705E74010BF0DDB5ABA27E4BBF9244700A382CC37E74B289A8A18A1E5F028635C664730A
# 7478BA4DCF425D2CB1192F91857A47FA82F5C984547BCC0ABD4DB4477232D408F1FD38D7549982CDF097AA20C8C132B5BB4867030D409F2F8655147B64C4880F
# 62E6140919560400B327F7D82FE5079CF797A8B4E6330D84C17DF8FCB16DB50B2FACA3B4EFC36A037FDF5779DB6EC4CB403415FD6EE6CB4A6BA4912634595C04
# 7B5285D171303E01B72F4072A3442196B5106E755A8EAF23ECB1CB5DED882D0927FA83D9626D8397C0F2579857E1456641B9307ABA500D9DF0BEF5A03DBBE402
# 33923A08169BE52AA63056AC910EDE2D4D009B3BACA107708E8EFD63960DBF011CD27EE4CFBA5AD8AF321B0D210A57DD8A8ED40CFC3100316D791BAA72B28F03
# 0FD89DF188499DE2E2C4EA7106F82088B44A02BCEAF1685C2C44443079ED4C0EB450E6CD606CD07B07B9115B1C3183B6DC1BAA8AEC63C5F22F07B4121600D707
# 4E28FAD8EA66FEA1F35BA08C42CEED3B63A8ED732BF6086110142BBDC449EC0BD2B6EB9E56EC92BE4685D1877B6761EEB90F773A0B29A0C062C4053292C6680C
# 19F93B27B20FAE7F7597A70F6623BB6692499CC24A79BF6D8200C38159DB6E08C613014DBCF76E931B80413BB36B8D44324D948CF8A8747B70D49D9585A49803
```

```sh
./zig-out/bin/shamir reconstruct -m s25519 -s=13EA9709CC727E0CA9318D88952857DC09C4623D4BECFA80BB4A11BC3590D90F95A112BB916F7310A1096D8BBFD8F2CE8510DB466591B5C30F5D7C6709BD0C0B,7478BA4DCF425D2CB1192F91857A47FA82F5C984547BCC0ABD4DB4477232D408F1FD38D7549982CDF097AA20C8C132B5BB4867030D409F2F8655147B64C4880F,33923A08169BE52AA63056AC910EDE2D4D009B3BACA107708E8EFD63960DBF011CD27EE4CFBA5AD8AF321B0D210A57DD8A8ED40CFC3100316D791BAA72B28F03,4E28FAD8EA66FEA1F35BA08C42CEED3B63A8ED732BF6086110142BBDC449EC0BD2B6EB9E56EC92BE4685D1877B6761EEB90F773A0B29A0C062C4053292C6680C
# --- output ---
# secret: 2BEC57FD2D5092059C411411B8058C92750FE73CBDEEA718B366DB62EB0EAA09
```

#### Feldman Ed25519 via Ristretto255

```sh
./zig-out/bin/shamir generate --threshold 4 --total 10 --secret mynamejeff -m f25519
# --- output ---
# secret (hashed): 6D33F29E352F4A76FB61C06E6AC84163760FE73CBDEEA718B366DB62EB0EAAA9
# secret (hashed + reduced): 2BEC57FD2D5092059C411411B8058C92750FE73CBDEEA718B366DB62EB0EAA09
#
# shares (4/10 required):
# 49814F39B575396032A86C3F6EF9F0EBDBC0A88FEC19CAB98A36414097399B0803B3667FAB8A806FFC4B99438D7E11B329E29C3AC62E4917A96EBAD33C4EAB01
# 049667BC415BCABB0619AC12A08B9303331A8A3217B51BFE17EFD30677D16B06790F10EDC8B5E124B1F1CA7BF80C29A7F7AEFE8B77B5E02E669BAAABDDC24605
# 92CD16899DC5FB48314E7512881714B280CEC260E01C43DC9318105DC6E6EB0E507EB0C564C26C724229D68A894F870DC5116F50E68D9B784DBC9A3302F4BD07
# EB6BE224F74F1906383AC8BBD4E182FD459A29EF3EEC1AE606A40877E12704069139983309B233A300F7269BF23822E4FF89BF97E62DFFC908C31BD5F4286205
# ED8F45DDC5B003B56ED684BD38FE7D577AF752EFA17389016073058487C9D8089EA3F6D862F58221F323749C2473C8C4C98A01B7CDB8110FD08CDB6986B44F0F
# F7E224EA86853ACB60A68ECA39862C2D69F23620358E144213E6DBB18CA439087E5387849AE26580445838F9A3459B27AE732EA095F7E6D1A8FDB2C84631600B
# 477E6A586D37E1BE6F7CE83EA87AABF850F909E2B28446659311BF07DBE9C705790F15B3E7F5EFDB3D0130CD733B02EEE19A8CC76DE1A9720914B95F87237F0F
# 5A8C11E5983CB5C91D259CA58EB1827705E83350754BABFA8D0AE7F1B3FC0303808D134C8B66D150FBA1AD081F7D7146BFCF507BDEF4FFA2C774AF229793090B
# 0802CE0B329158BCF5DB3258AB2D25D8CC9637DAA8B9C9E262BEA98556262204CD3BE0D6116E6E9E6EF2644DDE787FC08A81B9440250FB50BB9B2AEFFDAF1801
# 6B3F0CCA128D3315B8D298006E3EDCF9A08DDD3525DA04258DCD20EACD85940FDCAFB5619158459A036EF258327FB1CFC7A3F0E33C5926AA0D9839802D60C609
#
# commitments:
# 6619F19D0BB5D506EB91979E1DC11F4754FFB35CAC987486F8128A36FB67240A
# 680D5DFF0FD0D5AD95EF878E9D5427BCFFD4A38BAD5448768CCCFB3B28F5F902
# B4B1E9FFE8E15C4D786A40792E9A82F7748841CBEC64D55B50BDCB249BC5CC70
# D2E9B85F819DE590B4362B4C8D5462C95EF2DA32CD28D8430CAFAB45FA17E820
```

```sh
./zig-out/bin/shamir verify -m f25519 -s 49814F39B575396032A86C3F6EF9F0EBDBC0A88FEC19CAB98A36414097399B0803B3667FAB8A806FFC4B99438D7E11B329E29C3AC62E4917A96EBAD33C4EAB01 -c=6619F19D0BB5D506EB91979E1DC11F4754FFB35CAC987486F8128A36FB67240A,680D5DFF0FD0D5AD95EF878E9D5427BCFFD4A38BAD5448768CCCFB3B28F5F902,B4B1E9FFE8E15C4D786A40792E9A82F7748841CBEC64D55B50BDCB249BC5CC70,D2E9B85F819DE590B4362B4C8D5462C95EF2DA32CD28D8430CAFAB45FA17E820
# --- output ---
# share validity: true
```

```sh
./zig-out/bin/shamir reconstruct -m f25519 -s=049667BC415BCABB0619AC12A08B9303331A8A3217B51BFE17EFD30677D16B06790F10EDC8B5E124B1F1CA7BF80C29A7F7AEFE8B77B5E02E669BAAABDDC24605,477E6A586D37E1BE6F7CE83EA87AABF850F909E2B28446659311BF07DBE9C705790F15B3E7F5EFDB3D0130CD733B02EEE19A8CC76DE1A9720914B95F87237F0F,6B3F0CCA128D3315B8D298006E3EDCF9A08DDD3525DA04258DCD20EACD85940FDCAFB5619158459A036EF258327FB1CFC7A3F0E33C5926AA0D9839802D60C609,49814F39B575396032A86C3F6EF9F0EBDBC0A88FEC19CAB98A36414097399B0803B3667FAB8A806FFC4B99438D7E11B329E29C3AC62E4917A96EBAD33C4EAB01
# --- output ---
# secret: 2BEC57FD2D5092059C411411B8058C92750FE73CBDEEA718B366DB62EB0EAA09
```

#### Pedersen Ed25519 via Ristretto255

```sh
./zig-out/bin/shamir generate --threshold 4 --total 10 --secret mynamejeff -m p25519
# --- output ---
# secret (hashed): 6D33F29E352F4A76FB61C06E6AC84163760FE73CBDEEA718B366DB62EB0EAAA9
# secret (hashed + reduced): 2BEC57FD2D5092059C411411B8058C92750FE73CBDEEA718B366DB62EB0EAA09
#
# shares (4/10 required):
# 4F68C05ABAF05C8719A63DD4FB956A89535F62A483600B77BF2A6AF23DB84304A342502F83161846C1C0BC27ACF77643B325452BB0227663785C673C35ABED0F2C84B12AA73F387B0A51145A32F97B31E45EDC0168AB4F8D1458A1D58E96C105
# CC49BF6CD19DF7F99BB1D0DF8BBE71D299521C743F2DB0A8C553E8AB7B3E83006EB2B8A2F5996EF40C63040E36AB28ED768A69CDFAFFDC3E18BDF77E25E740036BDA64257A15DB50F03ECE29024292EA261AAFF2B488A2FBC98D0F9C921E7603
# A4871FCCC96F25AA189442680993A92FBCD5712EE19C57196A0C25910F7E3C03D94313D9201A8156AB1666E2AF15740F59E7DCF63B5AEBFFCEDE47BE3D77E205C05CA67302B95F14D03FBA9EBA2137EA4543ADA629F351A7E668B81936286302
# 9375125C44F6BC9D0394D0399E054D8BE5AD969730F0161D30A7EBB96FCECD0CD1D6A39F502B16FA2919B28C12F2C589621D1F0832D1791DC212163CEB7A5C08AE2B065035382A231F6D157F26335AA625487632B5BED2E608F384FA8CAD9305
# F8628F8C5202B305A8D34074F12409360A859510C22F63D7460CC7804D32930DC22B9F7CDE3E8B19DC5E04B3F1B36EE4C267C58AEC34CE6E6FB3DB00874E510A30139F19FD461DBBF6FE12DF04D4C67192FD9F2AD6C469C95F39A55FEB97C009
# F80E4B88E300320D8125E04F77FD13C604E3FF6AD7EFABE81D562FC3B8ABAA0A445346214009220C3172C52FA30DDE43D8D72451F8035160B6E40E464EAD850D45406A2C7924E0AFF59DEB3456BC6CB29DCC0F3BC8F265E5FC983C3CB55F3B0D
# 979A90B0016233C68869A0669DDA77F54A8CBD9CB3832418B73EAFA92519C203862E17117099F859DAC70396F882D74F3E61F9AC10A678B0D79CD7F08F5EB607F5AD016F9E3F9CFF189E88BB3D3038BF1EFD70CA057FD382C7C5BE9E0FF93306
# 2AC74EEFD7FEE98583E2123689A0A7324682C39D68B31C94ED7798476E367E0FB3074A938D628FC8B0F77E72DD98F143210793F942B4E67764AA36481ACFCC034626C13127D7373C6850B4BEA29D91E25423ECF54D24373223D94710B71EB700
# AB39FCE99366998F671E8C39913AF1DBE39FB012973BDFBF8F5A3D297786110C730F4A3A777363016B558439BE94B443814E70F54885F24F899185112704E40F941F85A9B401FBD5260A00173C5380CF2640226A319B3EEF3C4E8BD3B060E60F
# 37F7F7A9D1A655A3F74AFF1A45CDA380A17E3714E86A994F23516341B898A10E3BCB35FE3CC68C114900E73377618BDC19E010E1AC609766667ED3E181660502CC3555C53BD31DDD3F2A3378B7D7B62A81641A1235F80C57CD1943D7C2390D08
#
# commitments:
# BE62A4FDA40E9EE9BDBB7FFF5CC309AB1C3BA96B25DF151566CBF21028E3A952
# 305355D39AE9C1D3048153FC9B46E9D0264B67F18B49F7C47F9D393BF3E67842
# A2D0682D0FB13B0315337C38FB3B6583C7249DCE705A764D2C3B606DBC955D32
# 0CEF43C0C3A7786FA8F3F918DE1BFFA67679003CAC4254E1DA3DCF11DE3A9E2E
```

```sh
./zig-out/bin/shamir verify -m p25519 -s CC49BF6CD19DF7F99BB1D0DF8BBE71D299521C743F2DB0A8C553E8AB7B3E83006EB2B8A2F5996EF40C63040E36AB28ED768A69CDFAFFDC3E18BDF77E25E740036BDA64257A15DB50F03ECE29024292EA261AAFF2B488A2FBC98D0F9C921E7603 -c=BE62A4FDA40E9EE9BDBB7FFF5CC309AB1C3BA96B25DF151566CBF21028E3A952,305355D39AE9C1D3048153FC9B46E9D0264B67F18B49F7C47F9D393BF3E67842,A2D0682D0FB13B0315337C38FB3B6583C7249DCE705A764D2C3B606DBC955D32,0CEF43C0C3A7786FA8F3F918DE1BFFA67679003CAC4254E1DA3DCF11DE3A9E2E
# -- output ---
# share validity: true
```

```sh
./zig-out/bin/shamir reconstruct -m f25519 -s=049667BC415BCABB0619AC12A08B9303331A8A3217B51BFE17EFD30677D16B06790F10EDC8B5E124B1F1CA7BF80C29A7F7AEFE8B77B5E02E669BAAABDDC24605,477E6A586D37E1BE6F7CE83EA87AABF850F909E2B28446659311BF07DBE9C705790F15B3E7F5EFDB3D0130CD733B02EEE19A8CC76DE1A9720914B95F87237F0F,6B3F0CCA128D3315B8D298006E3EDCF9A08DDD3525DA04258DCD20EACD85940FDCAFB5619158459A036EF258327FB1CFC7A3F0E33C5926AA0D9839802D60C609,49814F39B575396032A86C3F6EF9F0EBDBC0A88FEC19CAB98A36414097399B0803B3667FAB8A806FFC4B99438D7E11B329E29C3AC62E4917A96EBAD33C4EAB01
# --- output ---
# secret: 2BEC57FD2D5092059C411411B8058C92750FE73CBDEEA718B366DB62EB0EAA09
```

### Code example

```zig
test "can split secret into multiple shares" {
    var secret = std.ArrayList(u8).init(std.testing.allocator);
    defer secret.deinit();
    // Hex value of "secret"
    try secret.appendSlice(&[_]u8{ 0x73, 0x65, 0x63, 0x72, 0x65, 0x74 });
    assert(secret.items.len == 6);

    const shares = try generate(secret, 3, 2, std.testing.allocator);
    defer {
        for (shares.items) |s| {
            s.deinit();
        }
        shares.deinit();
    }
    assert(shares.items.len == 3);

    const first_share = shares.items[0];
    assert(first_share.items.len == secret.items.len + 1);
    const second_share = shares.items[1];

    var thresholds = [2]std.ArrayList(u8){ first_share, second_share };
    const reconstructed = try reconstruct(&thresholds, std.testing.allocator);
    defer reconstructed.deinit();

    assert(std.mem.eql(u8, secret.items, reconstructed.items));

    std.debug.print("\nreconstructed (integers): ", .{});
    try std.json.stringify(&reconstructed.items, .{ .emit_strings_as_arrays = true }, std.io.getStdErr().writer());
    std.debug.print("\nreconstructed (string): ", .{});
    try std.json.stringify(&reconstructed.items, .{ .emit_strings_as_arrays = false }, std.io.getStdErr().writer());
}
```

See more in the tests at [shamir.zig](./src/shamir.zig), [feldman.zig](./src/feldman.zig), [pedersen.zig](./src/pedersen.zig)

## License

Apache-2.0. See the [license file](LICENSE).
