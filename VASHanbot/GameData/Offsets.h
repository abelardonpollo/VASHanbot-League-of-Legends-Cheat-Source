#pragma once
#include <Windows.h>
#include <cstdint>


#include "OffsetsChina.h"


inline  uintptr_t BaseAddress = 0;


#define DEFINE_RVA(address) ((uintptr_t)BaseAddress + (uintptr_t)address)


#define STR_MERGE_IMPL(x, y) x##y
#define STR_MERGE(x, y) STR_MERGE_IMPL(x, y)
#define MAKE_PAD(size) BYTE STR_MERGE(pad_, __COUNTER__)[size]
#define DEFINE_MEMBER_0(x) x;

#define DEFINE_CHARACTER_INTERMEDIATE(name) DEFINE_MEMBER_N(float name, (uintptr_t)Offsets::GameObject::CharacterIntermediate + (uintptr_t)Offsets::CharacterIntermediate::name)

#define DEFINE_MEMBER_N(x, offset) \
    struct {                       \
        MAKE_PAD((uint32_t)offset);   \
        x;                         \
    };



 

