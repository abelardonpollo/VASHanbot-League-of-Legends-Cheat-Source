#pragma once
#include <cstdint>

namespace Offsets
{

	enum class Hooks : uintptr_t
	{ // 14.1.553.2414
		OnWndProc = 0xdca380,
		OnUpdate = 0x3df590,
		OnObjectCreate = 0x3d9740,
		OnObjectDelete = 0x3c32f0,
		OnProcessSpell = 0x73efc0,
		OnSpellImpact = 0x736b10,
		OnDoCast = 0x243e20,
		OnStopCast = 0x73f5b0,
		OnPlayAnimation = 0x247f60,
		OnDrawing = 0x8ba290,
		OnUnderDraw = 0xeba5a0,
		OnRenderMouseOvers = 0x521cb0,
		OnNewPath = 0x3d9bc0,
		OnEnterVisibilityClient = 0x27DFDC,
		OnLeaveVisibilityClient = 0x2b2e30,
		OnFinishCast = 0x726c50,
		OnBuffAddRemove = 0x73d020,
		OnUpDateBuff = 0x6fad60,
		OnAggro = 0x247080,
		OnRecall = 0x0,
		OnReborn = 0x244b50,
		OnDead = 0x1bd280,
		OnUpDatePosition = 0x3d9670,
		OnUpDateLocalPlayer = 0x24d05c,
	};
	enum class Functions : uintptr_t
	{ // 14.1.553.2414
		WorldToScreen = 0xe99ac0,
		CastSpell = 0x73A790,
		UpdateChargeableSpell = 0x741a00,
		oIsCanSee = 0x2211b0,
		IssueOrder = 0x221950,
		evtPlayerMoveClickMouseTriggered = 0x8e8c90,
		evtPlayerCastClickKeyboardTriggered = 0x8c4ec0,
		evtCastSpellInputVal = 0x3fc220,
		oIsDead = 0x21ec50,
		oIsZombie = 0x2218d0,
		GetAttackDelay = 0x3c1e50,
		GetBoundingRadius = 0x20f580,
		GetAttackCastDelay = 0x3c1d50,
		oPathControllerCommon = 0x215910,
		oCreatePath = 0x29bf10,
		oCalculatePath = 0xe0a2b0,
		oSmoothPath = 0x2bf330,
		GetUnitInfoComponentPosition = 0x8bf8e0,
		GetOwnerObject = 0x211ca0,
		IsCastObjectWindingUp = 0x21e7e0,
		GetRespawnTime = 0x2162f0,
		GetSummonerEmoteDrawPosition = 0x216eb0,
		oUserObjectA = 0x20f940,
		oUserObjectB = 0x271F60,
		oGetPlayerName = 0x210AC0,
	};
	enum class RiotString : uintptr_t
	{ // 14.1.553.2414
		TranslateString = 0xd80ad0,
		TranslateObjectName = 0x2154c0,
	};
	enum class ManagerTemplate : uintptr_t
	{ // 14.1.553.2414
		Player = 0x2268538,
		AIBases = 0x224ab60,
		AttackableList = 0x224acc8,
		InhibitorList = 0x2269750,
		BuildingList = 0x224dd20,
		MissileList = 0x2269508,
		HeroesList = 0x224ac88,
		TurretsList = 0x22547a0,
		MinionsList = 0x224dd20,
		oIsDelete = 0x21e530,
		oIsMissile = 0x278f50,
		oIsMinion = 0x278f20,
		oIsTurret = 0x279070,
		oIsHero = 0x278ec0,
		oIsNexus = 0x278e80,
		oIsInhib = 0x278e00,
		oGetUnitByNetworkId = 0x3c83d0,
	};
	enum class GameClient : uintptr_t
	{ // 14.1.553.2414
		GameTimePtr = 0x224ab80,
		GetGameTime = 0xde6db0,
		GamePing = 0x4c25d0,
		GamePingPtr = 0x224ab50,
		Chatting = 0x22ae100,
		PrintChar = 0x847c20,
		PrintCharPtr = 0x22695a8,
		CastPingPtr = 0x0,
		CastPing = 0x0,
		WindowInfo = 0x22B4FE4,
	};
	enum class HudManager : uintptr_t
	{ // 14.1.553.2414
		Instance = 0x224ab70,
		ClientPosInstance = 0x224dce8,
		PosOffset = 0xc,
	};
	enum class GameRenderer : uintptr_t
	{ // 14.1.553.2414
		Instance = 0x22be108,
		DevicePtr = 0x18,
		r3dRendererInstance = 0x224dce0,
		RiotRendererMaterialRegistryGetSingletonPtr = 0xf062c0,
		Offset = 0x270,
		D3DDevice = 0x2b0,
		SwapChain = 0x1c0,
		ViewMatrix = 0x1a4,
		ProjectionMatrix = 0x1e4,
	};
	enum class SpellDataFunctions : uintptr_t
	{ // 14.1.553.2414
		GetRawDisplayName = 0x6c71e0,
		GetSpellSlot = 0x8c1320,
		GetTargettingType = 0x72b0e0,
		GetSpell = 0x8C1280,
	};
	enum class RenderPipelineLOL : uintptr_t
	{ // 14.1.553.2414
		GetInstance = 0xe82a80,
		ScreenBuffer = 0x0,
		DefaultMouseOverEffectData = 0x17c,
		RenderUsualSuspects = 0x0,
		fnDrawGlow = 0x630d20,
	};
	enum class Skin : uintptr_t
	{ // 14.1.553.2414
		ChampionManager = 0x224dd58,
		PushSkin = 0x1ab100,
		UpdateSkin = 0x194750,
	};
	enum class NavMesh : uintptr_t
	{ // 14.1.553.2414
		Instance = 0x224b0f8,
		GetCell = 0xe0e140,
		GetHeightForPosition = 0xE18AF0,
		IsNotWall = 0xe14590,
		IsWallOfType = 0xe15130,
		GetNearestTerrain = 0xe0e340,
		IsWater = 0xe154b0,
		IsInFoW = 0x2AC6E0,
	};
	enum class SpellbookClient : uintptr_t
	{ // 14.1.553.2414
		ActiveSpellInstance = 0x38,
		SpellSlotInfo = 0x6d0,
		GetSpellState = 0x71c560,
	};
	enum class GameTextureResources : uintptr_t
	{ // 14.1.553.2414
		Resources = 0x22b3bb8,
		AddPosition = 0xebda80,
		AddTexture = 0xebdb40,
		Refresh = 0xeba8f0,
		GetTexture = 0xe89320,
		Instance = 0x224dc58,
		TextureInstance = 0x224dd18,
		TextureOffset = 0x58,
	};
	enum class MiniMap : uintptr_t
	{ // 14.1.553.2414
		Instance = 0x225ae40,
		MiniMapInfo = 0x290,
	};
	enum class GameStatus : uintptr_t
	{ // 14.1.553.2414
		Instance = 0x224dd68,
		offset = 0xc,
	};
	enum class ZoomClass : uintptr_t
	{ // 14.1.553.2414
		Instance = 0x2250428,
		ZoomAmount = 0x20,
	};
	enum class MissionInfo : uintptr_t
	{ // 14.1.553.2414
		Instance = 0x224ab68,
		MapId = 0x8,
		MapName = 0x38,
	};


	enum class Temp : uintptr_t
	{
		DoCastCdAddress = 0x224AB58,
		DoCastCdOffset = 0x28
	};

	enum Shop
	{
		OnOpenShop = 0x00A8C590,
		OnCloseShop = 0x00A8CEB0,
		evtOpenShop = 0x00AE88F0,
		OnBuyItem = 0x005511F0,
		OnSellItem = 0x00590DA0,
		OnSwapItem = 0x00598F00,
		OnUpdateItem = 0x0055A4A0,
	};

	enum class HeroInventoryCommon
	{
		// x64 更新完毕
		Slots = 0x30,
		Slots6 = 0x30,
		Slots7 = 0x38,
		Slots8 = 0x40,
		Slots9 = 0x48,
		Slots10 = 0x50,
		Slots11 = 0x58,
		Slots12 = 0x60,
	};

	enum class ItemInfo
	{
		// x64更新完毕
		ItemData = 0x38,
		Ammo = 0x40,
		Price = 0x44,
	};

	enum class InventorySlot
	{
		// x64 更新完毕
		Stacks = 0x0,
		ItemInfo = 0x10
	};

	enum class ItemData
	{
		// x64 更新完毕
		ItemId = 0x9c,
		ItemTextureInstance = 0x4f8,
		DisplayNameLocalizationKey = 0x460,
		MaxStacks = 0xa0,

	};

	enum class NavigationPath
	{
		/*x64 更新完毕*/
		Index = 0x0,
		NavigationMesh = 0x8,
		StartPosition = 0x10,
		EndPosition = StartPosition + 0xC,
		Path = EndPosition + 0xC,
		PathSize = Path + 0x8,
		PathMaxSize = PathSize + 0x4,

		IsNoDashing = 0x39, // 冲刺 = 0 正常状态 = 1
		DashSpeed = 0x40,

	};

	enum class PathControllerCommon
	{

		/*x64 更新完毕*/
		MoveSpeed = 0x2b8,
		HasNavigationPath = 0x2bc,
		ServerPosition = 0x414,
		Velocity = 0x420,
		NavigationMesh = 0x2a0,
		NavigationPath = 0x2c0,

	};

	enum class BuffScriptInstance
	{
		/*x64 更新完毕*/
		Owner = 0x8,
		CasterId = 0x10,
		NetworkId = 0x14,
	};

	enum class BuffScript
	{

		/*x64 更新完毕*/
		Name = 0x8,
		NameSize = Name + 0x8,
		NameMaxSize = NameSize + 4,
		Hash = 0x18,
		Virtual_GetDisplayName = 14,
	};

	enum class BuffManager
	{

		/*x64 更新完毕*/
		BuffManagerEntriesArray = 0x18,
		BuffManagerEntriesArrayEnd = 0x20,
	};

	enum class BuffInstance
	{
		/*x64 更新完毕*/
		Script = 0x10,
		Type = 0x8,
		StartTime = 0x18,
		ExpireTime = 0x1c,
		CasterInfo = 0x30,
		Count = 0x38,
		CountMax = Count + 4,
		ScriptInstance = 0x40,
		IsPermanent = 0x88,
		Counter = 0x8c,

	};

	enum class SpellPosData
	{
		/*x64 更新完毕*/
		CurrentPos = 0x18,
		StartPos = CurrentPos + 0xc,
		MousePos = StartPos + 0xc,
		EndPos = MousePos + 0xc,
	};

	enum class SpellDataInst
	{
		/*x64 更新完毕*/
		IsLearned = 0x2c, // 是否学习
		ToggleState = 0x2d, // 切换状态 大眼的Q 默认是0 发射出去就是1
		Level = 0x28,
		CastTime = 0x30, // 释放时间
		Ammo = 0x5c, // 弹药
		AmmoRechargeTime = 0x68, // 弹药刷新时间
		AmmoCd = 0x6c, // 弹药CD
		SpellCD = 0x74,
		DirectionsBitfield = 0xe8,
		fEffect1 = 0x90,
		fEffect2 = fEffect1 + 0x4,
		fEffect3 = fEffect2 + 0x4,
		fEffect4 = fEffect3 + 0x4,
		fEffect5 = fEffect4 + 0x4,
		fEffect6 = fEffect5 + 0x4,
		fEffect7 = fEffect6 + 0x4,
		fEffect8 = fEffect7 + 0x4,
		fEffect9 = fEffect8 + 0x4,
		fEffect10 = fEffect9 + 0x4,
		fEffect11 = fEffect10 + 0x4,
		SpellPositionData = 0x128,
		SpellData = 0x130, //"SpellDataInstClient::SetSpellData: %s n"...
	};

	enum class SpellCastInfo
	{
		SpellData = 0x0008,
		SourceId = 0x90,
		StartPosition = 0xc0,
		EndPosition = 0xcc,
		MousePosition = 0xd8,
		TargetId = 0x100,
		CastDelay = 0x110,
		Delay = 0x120,

		Slot = 0x13c,

		CastTime = 0x150,
		StartTime = 0x18c,
		EndTime = 0x190,

		SpellCD = 0x124,

		IsBasicAttack = 0x108,
		IsSpecialAttack = 0x10c,

		IsCharging = 0x198,
		IsInstantCast = 0x19d,
		SpellWasCast = 0x19f,

		IsWindingUp = 0xEc,
	};

	enum class SpellDataInfo
	{
		/*x64 更新完毕*/
		SpellHash = 0x24,
		Name = 0x28,
		Resource = 0x60,

	};

	enum class SpellDataResource
	{
		/*x64 更新完毕*/
		MissileName = 0x80,  // x64
		SpellName = 0xb0,  // x64
		MissileSpeed = 0x500, // 0x4f0,

		CoolDown = 0x2f4,
		ManaCost = 0x604,
		LineWidth = 0x550,

		DisplayNameLocalizationKey = 0x204,
		eEffect1 = 0xe0,
		eEffect2 = eEffect1 + 0x1C,
		eEffect3 = eEffect2 + 0x1C,
		eEffect4 = eEffect3 + 0x1C,
		eEffect5 = eEffect4 + 0x1C,
		eEffect6 = eEffect5 + 0x1C,
		eEffect7 = eEffect6 + 0x1C,
		eEffect8 = eEffect7 + 0x1C,
		eEffect9 = eEffect8 + 0x1C,
		eEffect10 = eEffect9 + 0x1C,
		eEffect11 = eEffect10 + 0x1C,
		aEffect1 = 0x200,
		aEffect2 = 0x204,

		SpellTextureInstance = 0x290,

	};

	enum class CharacterProperties
	{
		// x64 更新完毕
		AttackRange = 0x250,
	};

	enum class CharacterData
	{
		// x64 更新完毕
		SkinName = 0x8,
		SkinHash = 0x18,
		Properties = 0x28
	};

	enum class MissileClient
	{
		/*x64 更新完毕*/
		MissileSpellCastInfo = 0x2e8,
		MissileClientSourceId = 0x370,
		MissileClientNetworkId = 0x37c,
		MissileClientStartPos = 0x3a0,
		MissileClientEndPos = 0x3ac,
		MissileClientCastDelay = 0x3d8,
		MissileClientDelay = 0x3e8,
		MissileClientTargetId = 0x3e0,
		MissileClientIsBasicAttack = 0x412,
		MissileClientIsSpecialAttack = MissileClientIsBasicAttack + 1,
		MissileClientSlot = 0x41c,
		MissileClientStartTime = 0x430,
		MissileClientEntTime = 0x488,
		MissileClientLineWidth = 0x48c,
	};

	enum class CharacterIntermediate
	{
		mAbilityHasteMod = 0x18,  // 技能急速
		mPassiveCooldownEndTime = 0x48,  // 被动冷却结束时间
		mPassiveCooldownTotalTime = 0x60,  // 被动冷却总时间
		mFlatPhysicalDamageMod = 0xC0,  //
		mPercentPhysicalDamageMod = 0xD8,  // 物理伤害的百分比
		mFlatMagicDamageMod = 0x120, // 用来乘的魔法伤害
		mPercentMagicDamageMod = 0x138, // 百分比魔法伤害
		mFlatMagicReduction = 0x150, // 用来乘魔法减少
		mPercentMagicReduction = 0x168, // 百分比魔法减少
		mAttackSpeedMod = 0x198, // 攻击速度
		mBaseAttackDamage = 0x1e0, // 物理攻击AD
		mBaseAbilityDamage = 0x240, // 基础法强
		mArmor = 0x2D0, // 护甲//
		mSpellBlock = 0x300, // 魔抗
		mAttackRange = 0x390, // 攻击范围
		mPercentArmorPenetration = 0x408, // 百分比护甲穿透
		mFlatMagicPenetration = 0x468, // 法穿
		mPercentMagicPenetration = 0x498, // 百分比法穿 假如是%40 那就是0.6
		mHPRegenRate = 0x330, // 基础血量恢复
		mCrit = 0x2a0, // 暴击
		mCritDamageMultiplier = 0x258, // 暴击伤害乘数
		mBonusArmor = 0x2e8, // 额外护甲
		mFlatBaseAttackDamageMod = 0x210, // 普通攻击伤害 用来乘的
		mPercentBaseAttackDamageMod = 0x228, // 百分比AD
		mBonusSpellBlock = 0x318, // 额外魔抗
		mPhysicalLethality = 0x3f0, // 护甲穿透
		mPercentBonusArmorPenetration = 0x420, // 百分比额外护甲穿透
		mPercentBonusMagicPenetration = 0x4b0, // 百分比法穿穿透
		mPrimaryARRegenRateRep = 0x5a0, // 基础MP恢复
		mMoveSpeed = 0x360, // 移动速度
		mPercentBonusPhysicalDamageMod = 0xf0,  // 物理伤害额外百分比
		mBonusAttackSpeed = 0x1b0, // 额外攻速
		mPercentDamageToBarracksMinionMod = 0x74,  // 对小兵伤害的百分比 可能
		mFlatDamageReductionFromBarracksMinionMod = 0x8c,  // 从兵营的伤害物理百分比减少
	};

	enum class GameObject : unsigned
	{
		Virtual_HashType = 1,
		Virtual_ShouldDrawHealthBar = 132, // 0F B6 56 01 48 8B CF 84 C0 0F B6 46 10 上面的CALL/ 8 就是偏移
		Virtual_ShouldDrawhighlight = 134,
		SourceId = 0x10,
		Team = 0x3c,
		ObjName = 0x60,
		NetworkId = 0xc8,
		mIsTargetable = 0xEE0,  //>ida
		mIsTargetableToTeamFlags = 0xEF8,  //>ida
		mCombatType = 0x26A8, //>ida
		Position = 0x280,
		mLevelRef = 0x4060, ////>ida
		mHP = 0x1088,
		mMaxHP = 0x10A0,
		mHPMaxPenalty = 0x10B8,
		mAllShield = 0x10E8,
		mPhysicalShield = 0x1100,
		mMagicalShield = 0x1118,
		mChampSpecificHealth = 0x1130,
		mIncomingHealingAllied = 0x1148,
		mIncomingHealingEnemy = 0x1160,
		mIncomingDamage = 0x1178,
		mStopShieldFade = 0x1190,
		mPAR = 0x370, // 蓝
		mMaxPAR = 0x388,
		mPARState = 0x3C8,
		mSAR = 0x418,
		mMaxSAR = 0x430,
		CharacterIntermediate = 0x1A20, // xref "mPhysicalDamagePercentageModifier"
		MissileState = 0x418,
		mExp = 0x4048, // 经验值 mLifetime 上一个
		HeroName = 0x38C0, // 0F ?? ?? ?? ?? ?? 48 8D ?? ?? ?? ?? ?? 48 83 ?? ?? ?? 72 ?? 48 8B 12 0F 57 C0
		RecallState = 0xf70,
		Spellbook = 0x2A50, // E8 ?? ?? ?? ?? 48 8B ?? ?? 48 8B ?? ?? F3 0F ?? ?? ?? ?? ?? ?? 48 8b
		Buffs = 0x27F8, // E8 ?? ?? ?? ?? 3C ?? 75 ?? 80 7B ?? ?? 74 ?? 4C 8B ?? ??  call进去 add rcx
		AttackData = 0x3570, // 74 ?? 41 8B C9 E8 ?? ?? ?? ?? 4C 8B ?? ?? ?? ?? ??  sub

		EncryptSkinId = 0x1244, // 40 38 BB ? ? 00 00 0F 85 ? 00 00 00 66 C7 83 ? ? 00 00 00 04 0F 31 48 C1 E2 ? 4C 8D 83 ? ? 00 00 48 0B C2 44 8B CF 48 89 45 ? 8B D7 41 BA ? 00 00 00 0F 1F 40 00

		BaseCharacterData = 0x3588,        // 48 8B ?? ?? ?? ?? ?? 48 85 C0 74 ?? 48 8B ?? ?? EB ?? 33 ED 85 DB 78 ??
		CharacterDataStack = 0x3628,        // 48 8D ?? ?? ?? 89 74 ?? ?? 48 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D ?? ?? ?? E8 ?? ?? ?? ??
		HeroInventory = 0x40a8,        // 48 8D ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 75 ?? 32 DB EB ?? B3 ?? 48 8D
		ActionState = 0x13E0 + 0x28, // 金身  = 0x0A000002 //ida 12.12
		ActionState2 = 0x13E0 + 0x40,
		StatusFlags = 0x520,  // //>ida
		UnitComponent = 0x35f8, // 48 8B 82 ?? ?? 00 00 48 8B FA 48 8B F1 48 85 C0 74 27
		PropertiesInstance = 0x28,
		PropertiesInstance_BaseHealth = 0xb0,
		PropertiesInstance_UpgradeHealth = 0xb4,
		PropertiesInstance_BaseMana = 0x11c,
		PropertiesInstance_UpgradMana = 0x120,
		PropertiesInstance_BaseAttackSpeed = 0x254,
		TextureInstance = 0x40,
		TextureLoadScreen = 0xb0,
		TextureCircle = 0x3b0,
		TextureSquare = 0x3c8,
		TransformedObject = 0x240,

		HpBarOffset1 = 0x3A40, // 74 ?? 48 8D ?? ?? ?? e8 ?? ?? ?? ?? eb 06 call进去
		HpBarOffset2 = HpBarOffset1 + 0x10,

		PerkManager = 0x43c0 + 0x2f8, // 48 89 ?? ?? ?? 48 8D ?? ?? ?? ?? ?? 4C 8B CB E8 ?? ?? ?? ?? 48 8B CB E8 ?? ?? ?? ??  下面的 lea rcx就是偏移 || E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 48 8B D3 49 8B CF E8 ?? ?? ?? ?? E9 ?? ?? ?? ??    mov r8,[rcx+??]

		PerkInfoId = 0x8,
		PerkInfoName = 0x10,
		PrekInfoDisplayname = 0x20,
		PrekInfoTextureName = 0x90,

		IsVisible = 0x340,
		Facing = 0x21f8, // 41 0F B6 55 01 49 8B CF F2 0F 10 00 上面的偏移加call 进去偏移

		mGold = 0x2180,
		mGoldTotal = 0x2198,
		OverrideCollisionRadius = 0x634,
	};

	enum class VisibilityClientInst
	{
		NetworkID = 0x0,
		Postion1 = 0x30,
		Postion2 = 0x3c,
	};

	enum class VisibilityClient
	{

		VisibilityClientPtr = 0x10
	};


} // namespace Offsets
