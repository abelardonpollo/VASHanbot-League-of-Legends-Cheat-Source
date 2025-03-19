#pragma once
#include <functional>
#include <string>

#include "BotSDK.h"
#include "GameData/Offsets.h"


class DelayAction {
    static DelayAction* instance;

public:
    static DelayAction* GetInstance() {
        if (instance == nullptr) {
            instance = new DelayAction();
        }

        return instance;
    }
    struct Action {
        std::function<void()> CallbackObject;
        float                 Time;
        Action(float time, std::function<void()> callback);
    };

    std::vector<Action>* ActionList;
    DelayAction();

    void Add(float time, std::function<void()> func);

    void DelayAction_OnOnUpdate();
};







class Common  {
    static Common* instance;

public:
    static Common* GetInstance() {
        if (instance == nullptr) {
            instance = new Common();
        }

        return instance;
    }


    Common() = default;

    static bool IsGameReady();


    float Time();

    float TickCount();

    float   Time2();

    void DelayAction(float time, std::function<void()> function);

    void PrintChat(const std::string& text, int color = 0xffffff);


    void SetCursorPosition(const Vector3& pos);

    Vector3 GetCursorPosition();

    GameObject* GetLocalPlayer();

    uint8_t GetGameInputVal(InputGameEvents eventType);

    void OnUpdata();

    POINT GetWindowInfo();

    bool IsChatting();
};



