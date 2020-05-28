#https://medium.com/@cetfor/emulating-ghidras-pcode-why-how-dd736d22dfb

from ghidra.app.emulator import EmulatorHelper
from ghidra.program.model.symbol import SymbolUtilities

def getAddress(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

def getSymbolAddress(symbolName):
    symbol = SymbolUtilities.getLabelOrFunctionSymbol(currentProgram, symbolName, None)
    if (symbol != None):
        return symbol.getAddress()
    else:
        raise("Failed to locate label: {}".format(symbolName))

def getProgramRegisterList(currentProgram):
    pc = currentProgram.getProgramContext()
    return pc.registers

def main():
    EIP = 0
    # Определяем эмулируемую функцию

    main_addr = getSymbolAddress("main")

    # Инициализируем эмулятор

    emuHelper = EmulatorHelper(currentProgram)

    # Создаем переменную для идентефикации возврата из эмулируемой функции

    controlledReturnAddr = getAddress(EIP)

    # Устанавливаем начальный адрес EIP

    main_addr = int("0x{}".format(main_addr),16)
    emuHelper.writeRegister(emuHelper.getPCRegister(), main_addr)

    # Для x86 `registers` содержит 812 регистров! 
    # Поэтому придется отфильтровать их, для вывода только тех, которые нам нужны

    registers = getProgramRegisterList(currentProgram)

    # А тут, те регистры, которые мы хотив видеть в выводе эмулятора

    reg_filter = [
        "EAX", "EBX", "ECX",
        "EDX", "ESI", "EDI", 
        "ESP", "EBP", "EIP",
        "flags"
    ]

    # Устанавливаем значение регистров

    emuHelper.writeRegister("EAX", 0x1337)
    emuHelper.writeRegister("ESP", 0xDEADBEEF)
    emuHelper.writeRegister("EBP", 0xDEADBEEF)

    # Для записи используем emuHelper.writeMemoryValue или emuHelper.writeMemory

    emuHelper.writeMemory(getAddress(0xDEAD0000), b'\x68\x65\x6c\x6c\x6f\x20\x67\x69\x74\x68\x75\x62')

    # Для чтение используем emuHelper.readMemory
    str_0 = emuHelper.readMemory(getAddress(0xDEAD0000), 12)

    t = []
    for i in str_0:
	    t.append(chr(i))

    print("Memory at 0xDEAD0000: {}".format(t))

    # Начало эмуляции

    while monitor.isCancelled() is False:
        executionAddress = emuHelper.getExecutionAddress()  
        if (executionAddress == controlledReturnAddr):
            print("Emulation complete.")
            return
        # Выводим состояние регистров 

        print("Address: 0x{} ({})".format(executionAddress, getInstructionAt(executionAddress)))
        for reg in reg_filter:
            reg_value = emuHelper.readRegister(reg)
            print("  {} = {:#010x}".format(reg, reg_value))

        # Эмулируем следующую инструкцию

        success = emuHelper.step(monitor)
        if (success == False):
            lastError = emuHelper.getLastError()
            printerr("Emulation Error: '{}'".format(lastError))
            return

    # Очищаем ресурсы и освобождаем текущую программу

    emuHelper.dispose()

# Вызываем main
main()


