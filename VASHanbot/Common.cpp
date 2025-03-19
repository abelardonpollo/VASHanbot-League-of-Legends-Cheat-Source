#include "Common.h"
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <fstream>
#include "libs/lazy_importer.hpp"
#include "libs/nlohmann/json.hpp"

DelayAction* DelayAction::instance = nullptr;
Common* Common::instance = nullptr;

std::string decToHex(int dec) {
    std::stringstream stream;
    stream << std::hex << dec;
    return stream.str();
}

// 将单个整数表示的RGB颜色值转换为HTML颜色代码
inline std::string rgbToHtml(int rgb) {
    int r = (rgb >> 16) & 0xFF;
    int g = (rgb >> 8) & 0xFF;
    int b = rgb & 0xFF;

    std::string red = decToHex(r);
    std::string green = decToHex(g);
    std::string blue = decToHex(b);

    // 确保每个颜色值都是两位数
    if (red.length() == 1) {
        red = "0" + red;
    }
    if (green.length() == 1) {
        green = "0" + green;
    }
    if (blue.length() == 1) {
        blue = "0" + blue;
    }

    return "#" + red + green + blue;
}

DelayAction::Action::Action(float time, std::function<void()> callback)
{
	Time = time + Common::GetInstance()->TickCount();
	CallbackObject = callback;
}

DelayAction::DelayAction()
{
	ActionList = new std::vector<Action>;
}

void DelayAction::Add(float time, std::function<void()> func)
{
	Action action(time, std::move(func));
	ActionList->push_back(action);
}

void DelayAction::DelayAction_OnOnUpdate()
{
	for (int i = (int)ActionList->size() - 1; i >= 0; i--) {
		if (ActionList->at(i).Time <= Common::GetInstance()->TickCount()) {
			if (ActionList->at(i).CallbackObject) {
				ActionList->at(i).CallbackObject();
			}


			ActionList->erase(ActionList->begin() + i);
		}
	}
}

bool Common::IsGameReady()
{
	auto gameread_ptr = DEFINE_RVA(Offsets::GameStatus::Instance);

	if (*reinterpret_cast<uintptr_t*>(gameread_ptr) == 0)
	{

		return false;
	}
	gameread_ptr = *reinterpret_cast<uintptr_t*>(gameread_ptr);
	BYTE GiaTri = *reinterpret_cast<BYTE*>(gameread_ptr + static_cast<uintptr_t>(Offsets::GameStatus::offset));

	return GiaTri == 2;
}

float Common::Time()
{
	uintptr_t GameTimePtr = *(uintptr_t*)(DEFINE_RVA(Offsets::GameClient::GameTimePtr));
	typedef float(__fastcall* fnGetGameTime)(uintptr_t Ptr);
	fnGetGameTime pfnGetGameTime = (fnGetGameTime)(DEFINE_RVA(Offsets::GameClient::GetGameTime));
	return pfnGetGameTime(*(uintptr_t*)(GameTimePtr + 0x10));
}

float Common::TickCount()
{
	return Time() * 1000.0f;
}

float Common::Time2()
{
	uintptr_t GameTimePtr = *(uintptr_t*)(DEFINE_RVA(Offsets::GameClient::GameTimePtr));
	typedef double(__fastcall* fnGetGameTime)(uintptr_t Ptr);
	fnGetGameTime pfnGetGameTime = (fnGetGameTime)(DEFINE_RVA(Offsets::GameClient::GetGameTime));

	return (float)pfnGetGameTime(*(uintptr_t*)(GameTimePtr + 0x20));
}

void Common::DelayAction(float time, std::function<void()> function)
{
	return DelayAction::GetInstance()->Add(time, std::move(function));
}

void Common::PrintChat(const std::string& text, int color)
{
	std::string str_assembly = "<font color=" + rgbToHtml(color) + ">" + text + "</font>";
	typedef  int(__fastcall* fnPrintChat)(uintptr_t ptr, const char*, int mode);
	const auto pfnPrintChat = reinterpret_cast<fnPrintChat>(DEFINE_RVA(Offsets::GameClient::PrintChar));
	uintptr_t ptr = *reinterpret_cast<uintptr_t*>(DEFINE_RVA(Offsets::GameClient::PrintCharPtr));
	pfnPrintChat(ptr, str_assembly.c_str(), 0x40);
}

void Common::SetCursorPosition(const Vector3& pos)
{
	uintptr_t Instance = DEFINE_RVA(Offsets::HudManager::Instance);
	uintptr_t ptr = *(uintptr_t*)Instance;
	if (!ptr)
	{
		return;
	}
	uintptr_t offset1 = *(uintptr_t*)(ptr + 0x28);
	if (!offset1)
	{
		return;
	}

	*(Vector3*)(offset1 + 0x2c) = pos;
}

Vector3 Common::GetCursorPosition()
{
	uintptr_t Instance = DEFINE_RVA(Offsets::HudManager::Instance);
	uintptr_t ptr = *(uintptr_t*)Instance;
	if (!ptr)
	{
		return {};
	}
	uintptr_t offset1 = *(uintptr_t*)(ptr + 0x28);
	if (!offset1)
	{
		return {};
	}

	return *(Vector3*)(offset1 + 0x2c);
}


GameObject* Common::GetLocalPlayer()
{
	auto Player = reinterpret_cast<GameObject*>(*reinterpret_cast<uintptr_t*>((DEFINE_RVA(Offsets::ManagerTemplate::Player))));
	if (Player == nullptr) {
		return nullptr;
	}

	return Player;
}



uint8_t Common::GetGameInputVal(InputGameEvents eventType)
{

    const char* events[] = { ("evtCastAvatarSpell1"),("evtCastAvatarSpell2"),\
        ("evtCastSpell1"), ("evtCastSpell2"), ("evtCastSpell3"), ("evtCastSpell4"),\
        ("evtUseItem1"), ("evtUseItem2"), ("evtUseItem3"), ("evtUseItem4"), ("evtUseItem5"), ("evtUseItem6"), ("evtUseItem7"), ("evtUseVisionItem") };


    static std::once_flag is_init;
    nlohmann::json jsonData = {};




#if defined(REGION_CN)
    std::ifstream ifs("Config\\PersistedSettings.json");
    if (jsonData.empty() && ifs.good())
    {
        jsonData = nlohmann::json::parse(ifs);
    }
#else
    char dir_buf[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, dir_buf);
    std::string filePath(dir_buf);
    std::string parentPath = filePath.substr(0, filePath.find_last_of("\\/"));

    std::ifstream ifs(parentPath + R"(\Config\PersistedSettings.json)");
    if (jsonData.empty() && ifs.good())
    {
        jsonData = nlohmann::json::parse(ifs);
    }
#endif

    // });
    ifs.close();

    if (!jsonData.empty())
    {
        std::string evt_val;
        for (const auto& section : jsonData["files"][1]["sections"]) {
            for (const auto& setting : section["settings"]) {
                //Utils::Out::Dedbg_ExA("%s", std::string( setting["name"]).c_str());
                if (setting["name"] == events[eventType] && setting["name"] != "null") {
                    evt_val = setting["value"];
                    break;
                }
            }
        }

        if (!evt_val.empty())
        {
            std::string::size_type pos = evt_val.find('[');
            while (pos != std::string::npos) {
                std::string::size_type end_pos = evt_val.find(']', pos);
                if (end_pos == std::string::npos) {
                    break;
                }
                std::string val_str = evt_val.substr(pos + 1, end_pos - pos - 1);
                if (val_str.length() > 1)
                {
                    if (val_str == "Space")
                    {
                        return 0x20;
                    }
                    return  0;
                }

                if (val_str[0] >= 'a' && val_str[1] <= 'z')
                {
                    val_str[0] -= 32;
                }

                return val_str[0];
            }
        }
    }
    return 0;
}

void Common::OnUpdata()
{
    DelayAction::GetInstance()->DelayAction_OnOnUpdate();
}

POINT Common::GetWindowInfo()
{
    return *(POINT*)(DEFINE_RVA(Offsets::GameClient::WindowInfo));
}


bool Common::IsChatting() {
	uintptr_t dw1 = DEFINE_RVA(Offsets::GameClient::Chatting);

	return *(BYTE*)dw1;
}