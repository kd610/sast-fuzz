#include "SVF-FE/LLVMUtil.h"
#include "SVF-FE/PAGBuilder.h"
#include "WPA/Andersen.h"
#include "container/FuncInfo.h"
#include "utils/IO.h"
#include "utils/LLVMUtils.h"
#include "utils/PrettyPrinter.h"

#include <iostream>

#define LLVM_MODULE(moduleSet) ((moduleSet)->getMainLLVMModule())
#define LLVM_DWARF_VERSION(moduleSet) (LLVM_MODULE(moduleSet)->getDwarfVersion())

using namespace std;

static llvm::cl::opt<std::string> inputFile(llvm::cl::Positional, llvm::cl::desc("<bitcode file>"));

static llvm::cl::opt<std::string> outputFile(llvm::cl::Positional, llvm::cl::desc("<JSON file>"));

vector<FuncInfo> getFuncInfo(SVF::SVFModule *svfModule) {
    SVF::PAGBuilder builder;
    SVF::PAG *pag = builder.build(svfModule);

    SVF::Andersen *ander = SVF::AndersenWaveDiff::createAndersenWaveDiff(pag);

    SVF::PTACallGraph *callGraph = ander->getPTACallGraph();

    vector<FuncInfo> funcInfos;

    for (auto callNode : *callGraph) {
        const llvm::Function &llvmFunc = *callNode.second->getFunction()->getLLVMFun();
        if (!llvmFunc.isDeclaration()) {
            auto optLineNumbers = LLVMUtils::getFunctionLines(llvmFunc);
            if (optLineNumbers.has_value()) {
                string name = llvmFunc.getName().str();
                string filename = LLVMUtils::getFilename(llvmFunc);
                Lines lineNumbers = optLineNumbers.value();
                LineRange lineRange = LLVMUtils::computeRange(lineNumbers);
                bool reachableFromMain = callNode.second->isReachableFromProgEntry();

                set<BBInfo> blockInfos;
                for (auto &bb : llvmFunc) {
                    auto optBBLineNumbers = LLVMUtils::getBBLines(bb);
                    if (optBBLineNumbers.has_value()) {
                        BBId id = LLVMUtils::getBBId(bb).value();
                        Lines bbLines = optBBLineNumbers.value();
                        LineRange bbLineRange = LLVMUtils::computeRange(bbLines);

                        blockInfos.insert(BBInfo(id, bbLines, bbLineRange));
                    }
                }

                funcInfos.emplace_back(FuncInfo(name, filename, lineNumbers, lineRange, reachableFromMain, blockInfos));
            }
        }
    }

    return funcInfos;
}

int main(int argc, char **argv) {
    int arg_num = 0;
    char **arg_value = new char *[argc];
    std::vector<std::string> moduleNameVec;
    SVF::SVFUtil::processArguments(argc, argv, arg_num, arg_value, moduleNameVec);
    llvm::cl::ParseCommandLineOptions(arg_num, arg_value, "SASTFuzz Inspector\n");

    SVF::SVFModule *svfModule = SVF::LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(moduleNameVec);

    assert(LLVM_DWARF_VERSION(SVF::LLVMModuleSet::getLLVMModuleSet()) > 0 &&
           "ERROR: Bitcode file doesn't contain debug information!");

    LLVMUtils::setBBIds(*LLVM_MODULE(SVF::LLVMModuleSet::getLLVMModuleSet()));

    vector<FuncInfo> funcInfos = getFuncInfo(svfModule);

    JSONPrinter printer;

    printer.printToFile(outputFile, funcInfos);

    return 0;
}