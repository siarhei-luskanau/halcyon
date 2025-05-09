plugins {
	application
	kotlin("jvm")
}

kotlin {
	jvmToolchain(jdkVersion = libs.versions.java.languageVersion.get().toInt())
}

application {
	mainClass.set("ping.ApplicationKt")
}

dependencies {
	implementation(libs.halcyon.core)
}