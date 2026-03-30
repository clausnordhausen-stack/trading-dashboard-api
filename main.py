import 'package:flutter/material.dart';

import 'app/app_session.dart';
import 'app/theme.dart';
import 'screens/app_shell.dart';
import 'screens/login_screen.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  try {
    await AppSession.initialize();
  } catch (e) {
    debugPrint('AppSession initialize error: $e');
  }

  runApp(const TradingSystemsDashboardApp());
}

class TradingSystemsDashboardApp extends StatelessWidget {
  const TradingSystemsDashboardApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Trading Systems Dashboard',
      debugShowCheckedModeBanner: false,
      theme: buildAppTheme(),
      home: const AuthGate(),
    );
  }
}

class AuthGate extends StatelessWidget {
  const AuthGate({super.key});

  @override
  Widget build(BuildContext context) {
    return ValueListenableBuilder<bool>(
      valueListenable: AppSession.isAuthenticated,
      builder: (context, isAuthenticated, _) {
        if (isAuthenticated) {
          return const AppShell();
        }
        return const LoginScreen();
      },
    );
  }
}
