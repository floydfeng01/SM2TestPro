package com.froad.sm2testpro.extension

class StringExtension {

}

fun String.allTrim () : String {
    return this.replace(Regex("\\s"), "")
}

fun String.startTrim () : String {
    return this.replace(Regex("(^\\s*)"), "")
}

fun String.endTrim () : String {
    return this.replace(Regex("(\\s*$)"), "")
}

fun String.startEndTrim () : String {
    return this.replace(Regex("(^\\s*)|(\\s*$)"), "")
}