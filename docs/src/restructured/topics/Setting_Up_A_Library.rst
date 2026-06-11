.. _header-setting-up-client:

Setting up a client
===================

Supported platforms
-------------------

Halcyon library can be used on different platforms:

* JVM
* Android
* iOS
* JavaScript

iOS support
^^^^^^^^^^^^^

Halcyon library supports compilation for iOS platform and provides proper Kotlin Multi Platform files as dependencies.

The best approach to use Halcyon in iOS application is to create Kotlin project for iOS and add Halcyon as dependency.

Then in the iOS application target will need to add a ``Run Script`` that will call Gradle to build you Kotlin project and embed and sign it for XCode as a framework.
You can achieve that with a following script:

.. code:: shell
   cd "{path-to-kotlin-project}"
   ./gradlew :embedAndSignAppleFrameworkForXcode

Additionally, as Halcyon for iOS depends on OpenSSL and LibSignal native frameworks, you may need to add those frameworks to your XCode project to include them in the application binary. Halcyon during build downloads required frameworks and places them at ``build/frameworks/`` directory (look for ``*.xcframework`` directories).

As Halcyon project is a library, it is not aware of the iOS lifecycle. It is also responsible for opening TCP sockets which need to be closed before iOS application will be suspended (moved into background without any background tasks). To achieve that, before application is suspended (ie. in ``applicationDidEnterBackground``) you need to call ``Halcyon::disconnect()`` method to disconnect from the XMPP server and close the socket. Without that, you may receive application crash reports caused by ``0xdead10cc``.

Adding client dependencies
--------------------------

To use Halcyon library in your project you have to configure repositories and add library dependency.
All versions of library are available in Tigase Maven repository:

Production
   .. code:: kotlin

      repositories {
          maven("https://maven-repo.tigase.org/repository/release/")
      }

Snapshot
   .. code:: kotlin

      repositories {
          maven("https://maven-repo.tigase.org/repository/snapshot/")
      }

At the end, you have to add dependency to ``tigase.halcyon:halcyon-core`` artifact:

.. code:: kotlin

    implementation("tigase.halcyon:halcyon-core:$halcyon_version")

Where ``$halcyon_version`` is required Halcyon version.
