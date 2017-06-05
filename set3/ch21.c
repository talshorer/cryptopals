#include <stdio.h>

#include <cryptopals/core.h>
#include <cryptopals/set3.h>

#define SEED 7

static mt19937_int_t test_numbers[] = {
	327741615UL,
	976413892UL,
	3349725721UL,
	1369975286UL,
	1882953283UL,
	4201435347UL,
	3107259287UL,
	1956722279UL,
	4200432988UL,
	1322904761UL,
	2312822158UL,
	1133316631UL,
	2152296008UL,
	372560217UL,
	309457262UL,
	1801189930UL,
	1152936666UL,
	68334472UL,
	2146978983UL,
	2266732518UL,
	2917270596UL,
	3731473840UL,
	3452032895UL,
	1420943751UL,
	1636129708UL,
	1687674368UL,
	283194443UL,
	2896227127UL,
	1237575930UL,
	2887580678UL,
	3906674451UL,
	2980842940UL,
	916483116UL,
	1485942463UL,
	1941857605UL,
	3992293176UL,
	3999499416UL,
	1127788727UL,
	106941365UL,
	3224501360UL,
	2579337979UL,
	1094761661UL,
	4080775104UL,
	3656282402UL,
	989143352UL,
	747550921UL,
	2355746254UL,
	3396303398UL,
	3904676612UL,
	4027087342UL,
	571958409UL,
	1927692119UL,
	2248039907UL,
	1652057283UL,
	3222985800UL,
	1535344467UL,
	2873390000UL,
	830456065UL,
	2008983232UL,
	431532432UL,
	879820150UL,
	2072909727UL,
	2107823453UL,
	2635836332UL,
	1599380060UL,
	4085580540UL,
	2050422343UL,
	1497897239UL,
	1571487242UL,
	1187621609UL,
	3598830371UL,
	1917728192UL,
	3301315901UL,
	4114208135UL,
	1348596887UL,
	771276892UL,
	2459407095UL,
	612959456UL,
	1185621653UL,
	358664548UL,
	1944945571UL,
	2350356961UL,
	1516030531UL,
	1332338555UL,
	2823509211UL,
	1214271969UL,
	1590645779UL,
	3955637147UL,
	1971789316UL,
	1861190419UL,
	3089473569UL,
	1798548603UL,
	1773786398UL,
	4235796153UL,
	3893058277UL,
	3408357193UL,
	775033821UL,
	1474484177UL,
	3183081343UL,
	1289946527UL,
	1814082690UL,
	2164470867UL,
	1831604146UL,
	2676863378UL,
	2724640789UL,
	2821674615UL,
	2245865027UL,
	1112979659UL,
	1781921722UL,
	1740316719UL,
	6128400UL,
	2865863180UL,
	396263773UL,
	1887643755UL,
	3046825705UL,
	3357528457UL,
	2252047180UL,
	2940458819UL,
	2989986414UL,
	3163992718UL,
	4103705212UL,
	2102055188UL,
	2933092661UL,
	4097361916UL,
	228185999UL,
	660304699UL,
	1326512163UL,
	2787944240UL,
	2545174788UL,
	2394072875UL,
	1009834440UL,
	3730314714UL,
	4144518906UL,
	616877622UL,
	4058951211UL,
	1923734511UL,
	3643854039UL,
	2831385549UL,
	2028616114UL,
	2842021927UL,
	3614114947UL,
	3601616285UL,
	563115916UL,
	2287317452UL,
	1326000975UL,
	170278685UL,
	1988554376UL,
	410591798UL,
	3186209446UL,
	3431227765UL,
	2086603462UL,
	1728245397UL,
	587878444UL,
	2931108827UL,
	1475478151UL,
	2155744977UL,
	1393399786UL,
	1705865711UL,
	1290289349UL,
	3375056996UL,
	710823092UL,
	4085957609UL,
	1781989545UL,
	1107906589UL,
	1924663578UL,
	2232874816UL,
	3328171772UL,
	3728476350UL,
	3420472022UL,
	1972942562UL,
	2243648524UL,
	472470150UL,
	1978392040UL,
	3431688098UL,
	3342401979UL,
	2138546282UL,
	3810877038UL,
	846862196UL,
	2898754033UL,
	3762713949UL,
	3438031334UL,
	1151800554UL,
	4033452561UL,
	1017641989UL,
	174615375UL,
	1600274481UL,
	3760981430UL,
	1657443660UL,
	1187829353UL,
	1001116648UL,
	2043392988UL,
	754966710UL,
	3422062255UL,
	1711569317UL,
	3080531913UL,
	3614771799UL,
	631994005UL,
	3378982148UL,
	2829302235UL,
	2752133708UL,
	297435369UL,
	2130377035UL,
	1533606662UL,
	2031759224UL,
	3491076321UL,
	2036822485UL,
	1836978261UL,
	4052633246UL,
	2576355179UL,
	3168823772UL,
	3127428920UL,
	178554675UL,
	3527145719UL,
	3254641847UL,
	3266387577UL,
	2205040524UL,
	30680140UL,
	766332781UL,
	1804989348UL,
	1683633863UL,
	1989154901UL,
	4035520186UL,
	238368553UL,
	914478310UL,
	2325476239UL,
	3493080875UL,
	2610355515UL,
	1733657426UL,
	3558179391UL,
	2519947164UL,
	4045040016UL,
	798859141UL,
	550390819UL,
	3488898637UL,
	989692192UL,
	2494720629UL,
	2831063767UL,
	1919560671UL,
	568971425UL,
	3427733549UL,
	962410408UL,
	2337629812UL,
	2469016027UL,
	1797085582UL,
	728098861UL,
	82277225UL,
	3359652906UL,
	2936785760UL,
	3680682274UL,
	2096364639UL,
	144629616UL,
	947382455UL,
	2287692006UL,
	2364564370UL,
	3422880009UL,
	2244511689UL,
	4188193037UL,
	2094021973UL,
	1177931691UL,
	1129711617UL,
	726283551UL,
	2264675214UL,
	3765401808UL,
	4228248112UL,
	3904908953UL,
	2677583345UL,
	848397294UL,
	2703926433UL,
	1896355797UL,
	3908303827UL,
	3089078527UL,
	4133989714UL,
	3630729792UL,
	2512984525UL,
	722736954UL,
	708230410UL,
	2856019966UL,
	1681880500UL,
	3469626874UL,
	4056832539UL,
	2361004188UL,
	1474853896UL,
	707452663UL,
	3028254177UL,
	152595044UL,
	1988083673UL,
	1209178540UL,
	1661253374UL,
	3469778867UL,
	2269600566UL,
	192269610UL,
	3529131356UL,
	35289607UL,
	2742237937UL,
	1553131663UL,
	3706078848UL,
	273255634UL,
	2734290151UL,
	642038764UL,
	4291948208UL,
	99601856UL,
	2223848492UL,
	2253654537UL,
	1407102766UL,
	2992286136UL,
	424227810UL,
	1834180784UL,
	2434243199UL,
	577975723UL,
	924311045UL,
	1423168405UL,
	50641040UL,
	2535516137UL,
	1285120011UL,
	4040109930UL,
	167406752UL,
	4263002920UL,
	4192806436UL,
	1037676613UL,
	2368472988UL,
	45440363UL,
	308018781UL,
	3567573041UL,
	1460580157UL,
	3979772270UL,
	1043257834UL,
	1969686964UL,
	461068272UL,
	3313319647UL,
	3308544647UL,
	3720296540UL,
	1505822191UL,
	2618275642UL,
	805919410UL,
	3747905200UL,
	3919813454UL,
	102662703UL,
	3698603646UL,
	1166492606UL,
	1713254861UL,
	1190649043UL,
	2346497129UL,
	518112333UL,
	1934347800UL,
	3911484483UL,
	2978985863UL,
	130735665UL,
	918461930UL,
	2888627616UL,
	1390705697UL,
	306401611UL,
	3177815899UL,
	1549540420UL,
	784134374UL,
	1795723871UL,
	2989391485UL,
	779125499UL,
	2262309873UL,
	2237738557UL,
	852512606UL,
	2297772110UL,
	2793721708UL,
	1361693099UL,
	2189473356UL,
	3165769104UL,
	2959392113UL,
	688064122UL,
	2462854554UL,
	826816480UL,
	3307633020UL,
	1522613227UL,
	1688129377UL,
	1625113096UL,
	4117112500UL,
	885991006UL,
	4200700769UL,
	3945825999UL,
	888547734UL,
	3556634808UL,
	2044410037UL,
	459032098UL,
	3393726220UL,
	1586929924UL,
	549482540UL,
	999314743UL,
	3551913236UL,
	1937367851UL,
	1019779505UL,
	1186773266UL,
	4039698616UL,
	2155244181UL,
	3524700082UL,
	3962550393UL,
	222305686UL,
	1642872850UL,
	7965637UL,
	2792279911UL,
	760090871UL,
	2558173189UL,
	2312521349UL,
	3229615942UL,
	2310761951UL,
	264850589UL,
	2198033808UL,
	3198993322UL,
	1040180470UL,
	4064224174UL,
	26528836UL,
	2592268526UL,
	3183716454UL,
	1235146445UL,
	1931466178UL,
	2887803788UL,
	3756870454UL,
	3058226264UL,
	1661960189UL,
	2819432539UL,
	17867771UL,
	631060919UL,
	630115344UL,
	4181045742UL,
	157488508UL,
	4103340677UL,
	1169072232UL,
	1823752797UL,
	1127946313UL,
	2549652908UL,
	2616693431UL,
	170203431UL,
	636921038UL,
	4246152134UL,
	892044478UL,
	3516482946UL,
	3097856549UL,
	2733756758UL,
	1149281521UL,
	3268834094UL,
	794121481UL,
	807582371UL,
	3480456719UL,
	1321366420UL,
	390987424UL,
	1058252643UL,
	556926869UL,
	2560011462UL,
	2918845908UL,
	394728320UL,
	1931006164UL,
	3846615585UL,
	1673590293UL,
	1985460034UL,
	2842605835UL,
	1910454575UL,
	45026443UL,
	449731620UL,
	1123215816UL,
	2941640429UL,
	3230830251UL,
	3508532989UL,
	4026481351UL,
	2703897397UL,
	2902043399UL,
	1039479189UL,
	2140919934UL,
	3373356307UL,
	3330007015UL,
	625688406UL,
	2426879277UL,
	3553124786UL,
	1304905955UL,
	2494110590UL,
	2065558353UL,
	1242846753UL,
	1353042696UL,
	2204363636UL,
	163304143UL,
	2700896202UL,
	2443618066UL,
	1110633435UL,
	4233824699UL,
	3637435985UL,
	1603020762UL,
	1809270887UL,
	2919583616UL,
	3832560200UL,
	524391309UL,
	3588310168UL,
	397933836UL,
	426694321UL,
	2718514402UL,
	2775640259UL,
	1206371452UL,
	1333564000UL,
	1165669082UL,
	3238633809UL,
	3823457995UL,
	2330585217UL,
	874063653UL,
	1965372197UL,
	1250309046UL,
	3845571056UL,
	2350334921UL,
	245902171UL,
	3076444883UL,
	2393660971UL,
	2226314418UL,
	1408367444UL,
	3150712002UL,
	151497839UL,
	253286536UL,
	3236337402UL,
	2517843518UL,
	2412657748UL,
	2503081273UL,
	3840324991UL,
	2697487280UL,
	2569512394UL,
	3071683744UL,
	1447551230UL,
	1044740986UL,
	4231486189UL,
	3118084930UL,
	496988054UL,
	4168085372UL,
	225922755UL,
	1622492073UL,
	3146587164UL,
	728770229UL,
	1592895567UL,
	1524126708UL,
	1552480685UL,
	2597869158UL,
	3764676937UL,
	2417941353UL,
	1405715497UL,
	2680619300UL,
	3818176936UL,
	2970798860UL,
	2765907298UL,
	1854479012UL,
	1413257046UL,
	772739781UL,
	255690811UL,
	2650211663UL,
	1052736643UL,
	1816627365UL,
	4159303026UL,
	2716705878UL,
	1740611246UL,
	3883177998UL,
	687338468UL,
	2573404819UL,
	1279957170UL,
	951921004UL,
	3863648549UL,
	870149433UL,
	708569582UL,
	3987677527UL,
	3340883525UL,
	3593123544UL,
	579239179UL,
	1776608794UL,
	4129154549UL,
	3999135010UL,
	2277214800UL,
	1265178409UL,
	185413459UL,
	2893973282UL,
	3998419903UL,
	3080615922UL,
	1538566986UL,
	2958658372UL,
	3141430467UL,
	1137421828UL,
	2249308776UL,
	3787356295UL,
	397635818UL,
	1169345338UL,
	455520880UL,
	1186167042UL,
	640916263UL,
	3619238840UL,
	692348746UL,
	4254870600UL,
	226584413UL,
	2972155396UL,
	201920000UL,
	845270708UL,
	4073468529UL,
	291682263UL,
	392095252UL,
	2737866364UL,
	2183353821UL,
	4134902649UL,
	509511199UL,
	4138585456UL,
	922506801UL,
	1680342384UL,
	3277369578UL,
	3903814806UL,
	4029258398UL,
	1014091890UL,
	2017400640UL,
	3000068258UL,
	24232020UL,
	1015710799UL,
	4291566996UL,
	52777361UL,
	205184394UL,
	283326464UL,
	1672665984UL,
	3665070306UL,
	2315230883UL,
	2700096631UL,
	3829965942UL,
	4166793372UL,
	3535239593UL,
	2217750307UL,
	2617295701UL,
	1866425318UL,
	1711983789UL,
	3738234712UL,
	3584058812UL,
	3222554838UL,
	3732577367UL,
	469411292UL,
	3744803059UL,
	2989420427UL,
	3082225016UL,
	3827667979UL,
	419993461UL,
	583559574UL,
	1282388892UL,
	2026100644UL,
	2087019330UL,
	1459118173UL,
	2169187687UL,
	1995071337UL,
	3577164086UL,
	726860458UL,
	1021501178UL,
	1723383176UL,
	2854395558UL,
	1114849370UL,
	1607176337UL,
	236773520UL,
	3330672199UL,
	1708025462UL,
	840844344UL,
	2930815221UL,
	2047098628UL,
	1812482814UL,
	444780718UL,
	1594643523UL,
	910490864UL,
	2278276823UL,
	4016544686UL,
	2938790684UL,
	1357412012UL,
	486730020UL,
	3835307039UL,
	2771139888UL,
	2251864616UL,
	797598330UL,
	167646101UL,
	3898475707UL,
	3405830399UL,
	3214645568UL,
	223153180UL,
	1797946375UL,
	3551695403UL,
	2410843482UL,
	37791877UL,
	2777177420UL,
	2895286081UL,
	3330897109UL,
	711735897UL,
	2050361012UL,
	1472637937UL,
	1927329881UL,
	4092036086UL,
	2397719930UL,
	2088356885UL,
	176833126UL,
	2823624811UL,
	3194070392UL,
	3181432997UL,
	2877962009UL,
	472137086UL,
	1092905540UL,
	3602600349UL,
	3907101846UL,
	3925256224UL,
	3217961791UL,
	667526614UL,
	3619006178UL,
	2346076170UL,
	3747556685UL,
	1217645219UL,
	2192812961UL,
	3181053478UL,
	2004153703UL,
	121420400UL,
	3861179856UL,
	2201372612UL,
	1267492759UL,
	3405113856UL,
	2622578770UL,
	3155670985UL,
	1896908550UL,
	464646033UL,
	263531778UL,
	3577450510UL,
	4098774702UL,
	1021518146UL,
	1813226783UL,
	3469421448UL,
	2441366605UL,
	2135152092UL,
	1442557097UL,
	690741402UL,
	3438504551UL,
	3152680722UL,
	11271508UL,
	3469959703UL,
	3684634295UL,
	3001757596UL,
	1922862428UL,
	4143983483UL,
	2118778361UL,
	1100132047UL,
	1205466925UL,
	1012591457UL,
	3769530304UL,
	632348417UL,
	1787498264UL,
	2316732007UL,
	4160398138UL,
	1715619620UL,
	1687433770UL,
	1531851823UL,
	3617631062UL,
	1976993195UL,
	3113941889UL,
	1179149908UL,
	312237256UL,
	18298199UL,
	904633006UL,
	2026153779UL,
	2749086077UL,
	1184914971UL,
	4278225187UL,
	1931805902UL,
	353089686UL,
	3989488244UL,
	1711016537UL,
	768822389UL,
	21784253UL,
	2737971127UL,
	2050351897UL,
	2767740910UL,
	1141174814UL,
	1208145002UL,
	4290062924UL,
	2022448569UL,
	272502702UL,
	4164450285UL,
	2500128599UL,
	1470855014UL,
	4131484409UL,
	3059499256UL,
	4039319995UL,
	3608713816UL,
	419290454UL,
	1549156507UL,
	4241599874UL,
	4251648818UL,
	4242190738UL,
	2688087915UL,
	2070145509UL,
	2151715345UL,
	3352571956UL,
	3070504401UL,
	3134506500UL,
	1820335705UL,
	3358491869UL,
	3059419979UL,
	1433457253UL,
	1180267262UL,
	2319950047UL,
	3982329402UL,
	1435326979UL,
	2327712670UL,
	3298111437UL,
	1037876677UL,
	7009528UL,
	1877745383UL,
	2259348542UL,
	3844410368UL,
	97909226UL,
	3466276204UL,
	1272057976UL,
	2080778319UL,
	125285820UL,
	1510547189UL,
	4234311780UL,
	1615970348UL,
	372307597UL,
	4214201952UL,
	2665663604UL,
	481950263UL,
	313227258UL,
	3818328544UL,
	1722318518UL,
	3683402059UL,
	2164539627UL,
	963740865UL,
	147941728UL,
	1500484327UL,
	2392220038UL,
	2446241072UL,
	4106955139UL,
	3446250406UL,
	2833789495UL,
	4082131934UL,
	3833360260UL,
	4259785947UL,
	3459807848UL,
	1207880990UL,
	3175244570UL,
	826195246UL,
	3856829495UL,
	2094763561UL,
	3777352502UL,
	2394718707UL,
	4287183642UL,
	2820525147UL,
	727359193UL,
	462100415UL,
	1426692034UL,
	2776077973UL,
	1704984812UL,
	3957293012UL,
	3587909322UL,
	3930758641UL,
	4240227681UL,
	4053478437UL,
	4000889644UL,
	3961418417UL,
	967071442UL,
	4126509357UL,
	504642385UL,
	209132855UL,
	3016407534UL,
	3934268177UL,
	1557908706UL,
	1164850120UL,
	3778620278UL,
	1377248845UL,
	1983056958UL,
	1969733167UL,
	1926207557UL,
	4102898070UL,
	948617768UL,
	2598837043UL,
	3231813586UL,
	1514805825UL,
	945099693UL,
	1606994869UL,
	1582082080UL,
	3886638260UL,
	3317084531UL,
	3531955911UL,
	1009132420UL,
	590720029UL,
	1393168460UL,
	1068080484UL,
	302431232UL,
	1597492453UL,
	3556303874UL,
	930899759UL,
	2142952789UL,
	2420135702UL,
	2657208649UL,
	960521182UL,
	1085282134UL,
	2469281911UL,
	2940592565UL,
	4020195159UL,
	159767467UL,
	3645035572UL,
	1049266954UL,
	426333320UL,
	2097465163UL,
	888649335UL,
	4078401831UL,
	1772744504UL,
	2278031683UL,
	2775096815UL,
	1448907379UL,
	1660289863UL,
	4041228912UL,
	1080666896UL,
	1783794246UL,
	1480299271UL,
	3857253709UL,
	876231696UL,
	279859964UL,
	3701689346UL,
	4007839079UL,
	2994673284UL,
	2898377666UL,
	1765356573UL,
	1145918693UL,
	3008330061UL,
	3926190271UL,
	2232220440UL,
	717196480UL,
	2260278997UL,
	1348446051UL,
	1577780331UL,
	584499439UL,
	2096881882UL,
	3674191581UL,
	4232760015UL,
	3725675140UL,
	3369250965UL,
	801176814UL,
	3554945691UL,
	3198256556UL,
	534173048UL,
	1397183946UL,
	2165840283UL,
	1284765120UL,
	1575827541UL,
	2670732057UL,
	381852525UL,
	2638885827UL,
	1697701893UL,
	1683794816UL,
	318633645UL,
	636371217UL,
	1005107018UL,
	1643831079UL,
	3430659735UL,
	1354250727UL,
	2947281602UL,
	2471148499UL,
	3000234966UL,
	3010417484UL,
	340839476UL,
	4039663384UL,
	704298498UL,
	3135424199UL,
	92703196UL,
	3341555301UL,
	418821703UL,
	1068841211UL,
	434731442UL,
	2975478972UL,
	4123790057UL,
	260466979UL,
	3839491424UL,
	2258516594UL,
	877264153UL,
	4021816489UL,
	1090118356UL,
	506048442UL,
	4126938931UL,
	3421082885UL,
	2448121270UL,
	698077052UL,
	1582795519UL,
	257236387UL,
	2003792463UL,
	3492489512UL,
	1169132804UL,
	3653037467UL,
	2506445320UL,
	2716981313UL,
	3115018772UL,
	788453634UL,
	2213833390UL,
	3379040747UL,
	3524735053UL,
	3727385352UL,
	486235541UL,
	3442625675UL,
	2592669760UL,
	2798825482UL,
	4250309481UL,
	4157184632UL,
	640289649UL,
	1570335137UL,
	2126163739UL,
	471150623UL,
	2706453387UL,
	1665092639UL,
	1449677796UL,
	3925535521UL,
	4142999817UL,
	4207000285UL,
	2084821838UL,
	292016194UL,
	2055995209UL,
	318474443UL,
	3876911094UL,
	2388737529UL,
	68334713UL,
	1068477761UL,
	3731833314UL,
	3997610687UL,
	554366033UL,
	2572537989UL,
	1628515951UL,
	2678774203UL,
	2097903270UL,
	1816029023UL,
	2046804018UL,
	2399427726UL,
	169258486UL,
	605936760UL,
	1361964753UL,
	736447958UL,
	1532421520UL,
	3021804400UL,
	4106758917UL,
	3488578417UL,
	3938422183UL,
	2743859324UL,
	2509758292UL,
	179402876UL,
	4008783746UL,
	3200870422UL,
	3709616516UL,
	1813823214UL,
	1613716705UL,
	1296578407UL,
	502368819UL,
	28000UL,
	2607635928UL,
	551618225UL,
	1387314998UL,
	222221194UL,
	41843728UL,
	2602030505UL,
	4214133216UL,
	1729443191UL,
	4163009139UL,
	1442575659UL,
	2305566138UL,
	2268699283UL,
	2655087378UL,
	1863930796UL,
	2872761042UL,
	2005718457UL,
	3979453440UL,
	1855192057UL,
	2007934476UL,
	2514158637UL,
	2503442709UL,
	2338706192UL,
	972980398UL,
	4285674971UL,
	1041092540UL,
	1633026514UL,
	2242454799UL,
	2305365354UL,
	984427770UL,
	3541768156UL,
	129934739UL,
	541570762UL,
	1582300143UL,
	1282917365UL,
	3220989868UL,
	1591889387UL,
	1190007385UL,
	1852671808UL,
	3705285208UL,
	2407423520UL,
	3017224743UL,
	4266931888UL,
	2805984206UL,
	2099531173UL,
	3833185914UL,
	1934122023UL,
	317015950UL,
	3644687899UL,
	767791539UL,
	3292398321UL,
	3905285872UL,
	1703185154UL,
	3895695862UL,
	3985008849UL,
	336155320UL,
	1131680385UL,
	3325299182UL,
	3993780034UL,
	66281714UL,
	3167502319UL,
	580832286UL,
	3083567433UL,
	471418071UL,
	3543976688UL,
	1262701380UL,
	2133870893UL,
	1667600172UL,
	1172240996UL,
	3912173470UL,
	2392363088UL,
	1874314309UL,
	4013885108UL,
	531927719UL,
	3361515245UL,
	1169728961UL,
	284403930UL,
	27388256UL,
	1630372655UL,
	120471290UL,
	551831167UL,
	1851424333UL,
	3086601675UL,
	2199831847UL,
	2855959435UL,
	1073576801UL,
	3414514469UL,
	1631625526UL,
	227165784UL,
	443966362UL,
	2836192212UL,
	2829617056UL,
	767853990UL,
	1686228089UL,
	2870381875UL,
	693747164UL,
	4188996434UL,
	2136289392UL,
	484928129UL,
	894963116UL,
	2422377290UL,
	1254685695UL,
	4170049738UL,
	533307952UL,
	1646845288UL,
	3353211906UL,
	3025628959UL,
	1199649767UL,
	1438650527UL,
	4104599985UL,
	1968203279UL,
	1741316781UL,
	4034153209UL,
	666555270UL,
	307897849UL,
	3028866644UL,
	1951771286UL,
	3150608264UL,
	65133457UL,
	3785239071UL,
	2280723911UL,
	564841770UL,
	3105081161UL,
	3392534363UL,
	3463908709UL,
	3692637181UL,
	1488017311UL,
	1307896122UL,
	3073584968UL,
	1951986086UL,
	3574875313UL,
	2661341934UL,
	3934509440UL,
	1054470943UL,
	1246651159UL,
	3742445152UL,
	3488814087UL,
	3003016448UL,
	1395086651UL,
	3679425694UL,
	140451803UL,
	1932370403UL,
	3406235898UL,
	2229081008UL,
	466235796UL,
	834316480UL,
	1141787451UL,
	1348724456UL,
	147754486UL,
	3133230850UL,
	2573275334UL,
	4118907042UL,
	515393392UL,
	653276849UL,
	1811360333UL,
	217512301UL,
	988939510UL,
	289707036UL,
	2868438916UL,
	1870337017UL,
	1801419966UL,
	3404497199UL,
	3832545428UL,
	965840529UL,
	1131826471UL,
	2049266646UL,
	2485048658UL,
	2213635551UL,
	418973783UL,
	3597904398UL,
	2620227088UL,
	704517265UL,
	1537011847UL,
	63215933UL,
	3725826375UL,
	2176066802UL,
	1368008739UL,
	1525769584UL,
	3571562944UL,
	1254840725UL,
	4070614877UL,
	3316733086UL,
	2997617737UL,
	2935468729UL,
	2076649005UL,
	360507320UL,
	1101308784UL,
	2354086025UL,
	233185921UL,
	3426716564UL,
	318040080UL,
	3907064463UL,
	4179464686UL,
	794218UL,
	1769794778UL,
	3468401273UL,
	2112197667UL,
	185748418UL,
	2539668499UL,
	2929685573UL,
	2253778765UL,
	2568420930UL,
	3349386720UL,
	4088878824UL,
	3278933798UL,
	2713900063UL,
	563420683UL,
	300386006UL,
	1201781567UL,
	2879337408UL,
	661120021UL,
	1094874879UL,
	615890475UL,
	3573172225UL,
	2729365134UL,
	135128658UL,
	970374583UL,
	1392152739UL,
	3564933258UL,
	2905269986UL,
	3814462074UL,
	668446385UL,
	1170476038UL,
	2775717130UL,
	3231083694UL,
	2994557753UL,
	1158270874UL,
	3151551093UL,
	208716654UL,
	3759536014UL,
	3130864135UL,
	1774534975UL,
	1645320413UL,
	611959710UL,
	4211982442UL,
	1118026925UL,
	2794587992UL,
	1673686060UL,
	929434312UL,
	234408888UL,
	2013773688UL,
	3043194073UL,
	455336479UL,
	270628649UL,
	4226466666UL,
	247857240UL,
	1206488654UL,
	4005055033UL,
	1060690915UL,
	3462799695UL,
	1168906UL,
	1089551777UL,
	3178220618UL,
	1467625087UL,
	3098634474UL,
	3547298096UL,
	2653266395UL,
	2659596076UL,
	702091313UL,
	1137812509UL,
	2383013663UL,
	1928522760UL,
	1320486142UL,
	3674600427UL,
	4201731696UL,
	2969337UL,
	3348014536UL,
	4262299223UL,
	157437183UL,
	2430666020UL,
	560673204UL,
	781770302UL,
	675075472UL,
	3436801925UL,
	1508056799UL,
	327255850UL,
	92661708UL,
	1760936940UL,
	570557267UL,
	2461584323UL,
	942114124UL,
	1061691622UL,
	3439615025UL,
	3802046013UL,
	2179729905UL,
	2993137100UL,
	2209711541UL,
	695046562UL,
	554846832UL,
	655409861UL,
	1786558544UL,
	266001059UL,
	249276228UL,
	2454567450UL,
	513415597UL,
	804305681UL,
	2702874419UL,
	2332092840UL,
	553671765UL,
	3519607492UL,
	739712722UL,
	3776070881UL,
	4205473283UL,
	499720895UL,
	3568966990UL,
	1426948867UL,
	2197204529UL,
	1792615046UL,
	2203349078UL,
	1646765533UL,
	2486558135UL,
	1798856694UL,
	387020487UL,
	1975631169UL,
	2816217677UL,
	3249358773UL,
	3334347603UL,
	1312180326UL,
	432417988UL,
	1474996281UL,
	147155152UL,
	1676088356UL,
	3007859787UL,
	649478355UL,
	3561961160UL,
	2707433279UL,
	4244345698UL,
	1719043580UL,
	3649410383UL,
	3934845372UL,
	915306088UL,
	3527954330UL,
	2245916803UL,
	988615165UL,
	3141055129UL,
	1040730588UL,
	3479607938UL,
	3359826593UL,
	2027182185UL,
	2404696171UL,
	366681310UL,
	43854655UL,
	3092408150UL,
	2705327129UL,
	999971060UL,
	1696138025UL,
	3664731990UL,
	3372467435UL,
	2467254663UL,
	3207683608UL,
	566519007UL,
	3961368637UL,
	3338299466UL,
	3003410383UL,
	1225683514UL,
	3921213167UL,
	2743334431UL,
	1222583166UL,
	107132569UL,
	1454772822UL,
	1457942308UL,
	254265686UL,
	4096143967UL,
	3723462238UL,
	3975023556UL,
	662359493UL,
	1137292983UL,
	2367899292UL,
	1390805540UL,
	2186977551UL,
	616720592UL,
	3495824557UL,
	152672789UL,
	1666402050UL,
	2875828885UL,
	612740125UL,
	681429508UL,
	1645320558UL,
	2721835157UL,
	206373180UL,
	463252269UL,
	1294802993UL,
	1659624775UL,
	2705841044UL,
	2868053268UL,
	245427924UL,
	4156129262UL,
	4250712910UL,
	3971428674UL,
	2302914607UL,
	1267167752UL,
	1288798791UL,
	1601339926UL,
	3581088934UL,
	1938539277UL,
	590408461UL,
	1327724952UL,
	1382824718UL,
	3499076688UL,
	4025028614UL,
	3715853980UL,
	1030504754UL,
	798941222UL,
	3147746878UL,
	1450411896UL,
	347593348UL,
	285176623UL,
	2286961134UL,
	3661839463UL,
	2826565688UL,
	1912366122UL,
	900753603UL,
	2819735251UL,
	1407160651UL,
	2313712734UL,
	2364418468UL,
	2242852031UL,
	2533966096UL,
	2945599357UL,
	662359362UL,
	3668042UL,
	1764263688UL,
	2457118189UL,
	4293820584UL,
	3299082882UL,
	1384847531UL,
	2125498911UL,
	3373078597UL,
	482604102UL,
	865925192UL,
	3107269088UL,
	1980812967UL,
	4046096766UL,
	2225521299UL,
	1151764711UL,
	2559879064UL,
	3093737643UL,
	3082296037UL,
	3324908476UL,
	3418409045UL,
	2235473072UL,
	3007188854UL,
	2300688948UL,
	3466899835UL,
	3879462049UL,
	3805176541UL,
	1707389578UL,
	1400671678UL,
	2143916986UL,
	3553266424UL,
	1102134931UL,
	2233289305UL,
	2925911701UL,
	1114234203UL,
	3368347860UL,
	743345902UL,
	1637592599UL,
	3283283459UL,
	3587464474UL,
	2734317161UL,
	3496198934UL,
	303788902UL,
	2719347805UL,
	2523094554UL,
	1422769630UL,
	191326293UL,
	286679497UL,
	1680431963UL,
	725078338UL,
	2453118823UL,
	2911146583UL,
	2792564798UL,
	1312445302UL,
	677972427UL,
	1044366179UL,
	192571886UL,
	3635853586UL,
	2474003231UL,
	3915422432UL,
	3516651599UL,
	2446504444UL,
	3421420908UL,
	927580778UL,
	1544727460UL,
	2124196638UL,
	2477986191UL,
	462368527UL,
	3086783883UL,
	2277549769UL,
	3750315555UL,
	3939869328UL,
	2111523121UL,
	1748595872UL,
	3760244364UL,
	1115407822UL,
	1364635147UL,
	1630247615UL,
	941680797UL,
	1104284323UL,
	1263249874UL,
	2503548944UL,
	3134327213UL,
	1888189589UL,
	3801649144UL,
	1012402035UL,
	2023712089UL,
	3788604578UL,
	2988943924UL,
	208131786UL,
	596200539UL,
	3135771769UL,
	2179392181UL,
	3352801041UL,
	1867628487UL,
	1249915926UL,
	1853726182UL,
	723803439UL,
	807645692UL,
	1550258267UL,
	2674824195UL,
	3517706445UL,
	2886528585UL,
	1866639321UL,
	2732989966UL,
	3080048205UL,
	3190114089UL,
	2612856264UL,
	1968054120UL,
	439889382UL,
	3661886932UL,
	2184803486UL,
	2453337703UL,
	2710964500UL,
	3787345128UL,
	1203963216UL,
	1761601248UL,
	434645337UL,
	3007072451UL,
	3270240725UL,
	845271173UL,
	365507767UL,
	356770017UL,
	3354156168UL,
	4000772317UL,
	2662073101UL,
	1592735983UL,
	2472852472UL,
	196273646UL,
	883153200UL,
	2656237607UL,
	1367514347UL,
	4008326448UL,
	1285363814UL,
	3302868509UL,
	2696916193UL,
	4240194060UL,
	2085177913UL,
	4016296616UL,
	1808754296UL,
	1956501387UL,
	2478951489UL,
	1004634709UL,
	3585522907UL,
	280197161UL,
	256535772UL,
	1168762465UL,
	3128887681UL,
	2715072780UL,
	1303470041UL,
	3912248454UL,
	969901999UL,
	7335267UL,
	2192721019UL,
	3511069066UL,
	772777526UL,
	3283351277UL,
	3015721113UL,
	2967747453UL,
	1338887635UL,
	549228246UL,
	1338212561UL,
	228730928UL,
	4148566694UL,
	3164335286UL,
	1327329501UL,
	2754831739UL,
	502604384UL,
	1588700156UL,
	330458694UL,
	1483945849UL,
	3120813180UL,
	140202192UL,
	944847032UL,
	4266767693UL,
	1721301774UL,
	3593350657UL,
	3443124254UL,
	4184117457UL,
	3608243170UL,
	3513444193UL,
	947756091UL,
	1970758259UL,
	1867429312UL,
	3629955155UL,
	3286538858UL,
	851938972UL,
	1805500677UL,
	2888256660UL,
	3274640211UL,
	1018849320UL,
	2340353985UL,
	1685677882UL,
	3545711149UL,
	3743837519UL,
	1765363471UL,
	1825151029UL,
	2481054801UL,
	3838481161UL,
	3878650649UL,
	2575087905UL,
	1460894594UL,
	1261630073UL,
	2938415654UL,
	1118224640UL,
	1225209308UL,
	14491456UL,
	2028405896UL,
	2457142397UL,
	1637902726UL,
	3601628892UL,
	737400176UL,
	965158492UL,
	3421841120UL,
	2058333393UL,
	3680099285UL,
	4225801441UL,
	1285853831UL,
	1689585796UL,
	3146790469UL,
	4030598460UL,
	2985550383UL,
	3550180069UL,
	3144545598UL,
	2124344862UL,
	3745420593UL,
	2728868317UL,
	1929612148UL,
	281677311UL,
	2597626721UL,
	2218061182UL,
	196400005UL,
	3263889880UL,
	1884708925UL,
	989416960UL,
	2357151271UL,
	221133712UL,
	453253456UL,
	126277176UL,
	524226892UL,
	688550870UL,
	2317465667UL,
	1021201492UL,
	1211810948UL,
	3459173894UL,
	2621079205UL,
	1971881934UL,
	1902179060UL,
	2300205702UL,
	2721164679UL,
	1344758790UL,
	2795202351UL,
	1283457893UL,
	1072531508UL,
	2377202081UL,
	1117365934UL,
	3203139403UL,
	3969449240UL,
	776058366UL,
	2498386992UL,
	1866805178UL,
	2770976890UL,
	2766332413UL,
	1592915599UL,
	4123571821UL,
	1348576491UL,
	1157080015UL,
	3301093967UL,
	1687338229UL,
	948593985UL,
	2445134727UL,
	3057849825UL,
	609445369UL,
	1942513821UL,
	2626728858UL,
	4068014363UL,
	4185261999UL,
	3011874094UL,
	1174331060UL,
	3756942798UL,
	2064082051UL,
	3927726235UL,
	505252496UL,
	2692428022UL,
	2225051835UL,
	4013483880UL,
	4172891084UL,
	2399342672UL,
	2329488309UL,
	1316815815UL,
	916981744UL,
	3654914021UL,
	1334692167UL,
	3074509808UL,
	2690399472UL,
	1509070925UL,
	3680887627UL,
	2860126458UL,
	1947500050UL,
	3224362249UL,
	2105049900UL,
	832646270UL,
	3476154633UL,
	1082562178UL,
	452233057UL,
	2180519492UL,
	4085568770UL,
	1660879326UL,
	1996150744UL,
	2562616261UL,
	1424425282UL,
	2006372145UL,
	3343824840UL,
	3941020354UL,
	1101541528UL,
	3717868797UL,
	628940542UL,
	2423374040UL,
	1108624177UL,
	3561095854UL,
	2888498086UL,
	1516946100UL,
	432365690UL,
	2520692426UL,
	1938357721UL,
	1582209223UL,
	1011719575UL,
	4020685331UL,
	2343669886UL,
	2700192386UL,
	593909961UL,
	3101720869UL,
	3324159787UL,
	3851476693UL,
	3968174261UL,
	1945822383UL,
	1371637384UL,
	2671579807UL,
	1522473853UL,
	3363898651UL,
	2568756546UL,
	255204949UL,
	3173200600UL,
	3555272771UL,
	250283574UL,
	1595879446UL,
	2898150301UL,
	1140425001UL,
	3497169571UL,
	1792561561UL,
	3403852702UL,
	348326664UL,
	1883778582UL,
	4226534903UL,
	3533772102UL,
	2109572933UL,
	2349676477UL,
	2377013079UL,
	801978144UL,
	740781227UL,
	1227230381UL,
	1447992287UL,
	2545781564UL,
	2756531370UL,
	2372861188UL,
	3842043130UL,
	3445286480UL,
	4098894466UL,
	3070444101UL,
	4256456879UL,
	915086391UL,
	923515798UL,
	1706761309UL,
	1909560703UL,
	3341803160UL,
	3293529044UL,
	1967602388UL,
	1029108016UL,
	966497618UL,
	383315777UL,
	4024791374UL,
	2334095354UL,
	1928764989UL,
	4253212795UL,
	1325972056UL,
	3368500805UL,
	2195837545UL,
	2171349792UL,
	1292434500UL,
	1759153300UL,
	1161289407UL,
	3944822943UL,
	2841257392UL,
	2742905196UL,
	3415501038UL,
	3886945312UL,
	1755918941UL,
	3547275978UL,
	691232763UL,
	1683365809UL,
	2043525618UL,
	4103866292UL,
	1724862071UL,
	797165339UL,
	1871365783UL,
	2735000458UL,
	1030259576UL,
	809126775UL,
	3305395537UL,
	1541602152UL,
	868560981UL,
	1827768486UL,
	165985544UL,
	3318961674UL,
	3006965123UL,
	3991450425UL,
	3189018142UL,
	77586487UL,
	1025463618UL,
	1271693302UL,
	744772736UL,
	2749764913UL,
	2493362853UL,
	1524013926UL,
	3949782628UL,
	2081940181UL,
	1090849953UL,
	436900439UL,
	2319300357UL,
	1391523603UL,
	1135495784UL,
	4253892866UL,
	3185352986UL,
	723150845UL,
	2006163717UL,
	1304743862UL,
	1627605131UL,
	755847229UL,
	2818102319UL,
	1432734246UL,
	2282429537UL,
	1592502958UL,
	863929876UL,
	3703575939UL,
	1787617976UL,
	2377571908UL,
	4108108349UL,
	2058431238UL,
	3440849559UL,
	1086839503UL,
	2199489712UL,
	1673499741UL,
	2836668068UL,
	207695495UL,
	611480623UL,
	513138150UL,
	1774652013UL,
	3223562731UL,
	3843207046UL,
	382651132UL,
	807970699UL,
	3877335166UL,
	4217320005UL,
	2539194992UL,
	3642609368UL,
	3833248669UL,
	2946897738UL,
	1995492925UL,
	1604703517UL,
	3064395059UL,
	395470066UL,
	3275187370UL,
	1265657316UL,
	2087355761UL,
	3182555646UL,
	1137030068UL,
	1810849974UL,
	2738747993UL,
	3448369272UL,
	1183802826UL,
	926838806UL,
	3319108368UL,
	3537962704UL,
	127084514UL,
	3694151120UL,
	2330117708UL,
	3101813187UL,
	2017560831UL,
	876234034UL,
	3119612442UL,
	957311452UL,
	3430427069UL,
	276142324UL,
	3864891045UL,
	220337625UL,
	843539939UL,
	3174279894UL,
	3717273480UL,
	2111047873UL,
	3358968479UL,
	3270665769UL,
	2578799150UL,
	1214385566UL,
	3352774364UL,
	1482909948UL,
	1112751364UL,
	3842722659UL,
	3965015992UL,
	4283729072UL,
	4189284443UL,
	437038436UL,
	1760900025UL,
	3346862257UL,
	1402615783UL,
	2388639962UL,
	2354660489UL,
	19536922UL,
	343733021UL,
	2648062706UL,
	3013733738UL,
	1202282420UL,
	1411555731UL,
	1505656900UL,
	1364905957UL,
	4163021148UL,
	239137705UL,
	3189777359UL,
	761477980UL,
	234169103UL,
	507868782UL,
	2924768792UL,
	1340223773UL,
	55815929UL,
	3082149889UL,
	3806173626UL,
	4156852755UL,
	2562731881UL,
	3051022126UL,
	2709356896UL,
	85438961UL,
	70646866UL,
	1233290179UL,
	359857568UL,
	513526872UL,
	2259809525UL,
	4268531171UL,
	1639537649UL,
	3523680000UL,
	3514552313UL,
	2702375608UL,
	1219650767UL,
	517543192UL,
	1716551010UL,
	4184323198UL,
	515390666UL,
	541517527UL,
	2159814178UL,
	2972241172UL,
	4101786423UL,
	2407204404UL,
	1142018371UL,
	947017068UL,
	3396595981UL,
	3330210906UL,
	704186144UL,
	543961103UL,
	3804924139UL,
	3428497857UL,
	2201742752UL,
	1802649985UL,
	540341974UL,
	273158973UL,
	3361656449UL,
	914928853UL,
	3812155881UL,
	3476844772UL,
	623032974UL,
	2016643080UL,
	504297564UL,
	237481491UL,
	1079705219UL,
	2725143625UL,
	2211686746UL,
	511359991UL,
	4080692887UL,
	756544171UL,
	3696245313UL,
	2424522543UL,
	1394257943UL,
	3729614775UL,
};

int main(int argcUL, char *argv[])
{
	unsigned int i;
	struct mt19937 mt;
	int ret = 0;

	mt19937_seed(&mt, 7);
	for (i = 0; i < ARRAY_SIZE(test_numbers); i++)
		if (mt19937_next(&mt) != test_numbers[i]) {
			printf("mismatch at index %d", i);
			ret = 1;
		}
	printf("tested %d numbers\n", i);
	return ret;
}
