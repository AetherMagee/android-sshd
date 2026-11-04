package io.github.aethermagee.sshd;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import java.io.File;

/** Shows (PROMPT) or dismisses (CANCEL) an approval notification for android-sshd. */
public class PromptReceiver extends BroadcastReceiver {
    static final String PKG = "io.github.aethermagee.sshd";
    static final String CHANNEL = "approvals";

    static boolean validId(String id) {
        return id != null && id.matches("[0-9a-f]{1,64}");
    }

    @Override
    public void onReceive(Context ctx, Intent in) {
        String id = in.getStringExtra("id");
        if (!validId(id)) return;
        NotificationManager nm = ctx.getSystemService(NotificationManager.class);
        if ((PKG + ".CANCEL").equals(in.getAction())) {
            nm.cancel(id, 0);
            return;
        }
        if (!(PKG + ".PROMPT").equals(in.getAction())) return;
        pruneAnswers(ctx);

        nm.createNotificationChannel(new NotificationChannel(CHANNEL, "SSH login approvals", NotificationManager.IMPORTANCE_HIGH));
        String text = in.getStringExtra("text");
        Notification.Builder b = new Notification.Builder(ctx, CHANNEL)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle(in.getStringExtra("title"))
                .setContentText(text)
                .setStyle(new Notification.BigTextStyle().bigText(text))
                .setCategory(Notification.CATEGORY_STATUS)
                .setTimeoutAfter(in.getIntExtra("timeout", 60) * 1000L)
                .setDeleteIntent(decision(ctx, id, "deny"));
        if (in.getBooleanExtra("window", false)) {
            b.addAction(action(ctx, id, "Allow 15 min", "allow 900", true));
            b.addAction(action(ctx, id, "Allow 1 h", "allow 3600", true));
        } else {
            b.addAction(action(ctx, id, "Allow", "allow 0", true));
        }
        b.addAction(action(ctx, id, "Deny", "deny", false));
        nm.notify(id, 0, b.build());
    }

    static Notification.Action action(Context ctx, String id, String title, String decision, boolean unlock) {
        Notification.Action.Builder a = new Notification.Action.Builder((android.graphics.drawable.Icon) null, title, decision(ctx, id, decision));
        if (unlock && Build.VERSION.SDK_INT >= 31) a.setAuthenticationRequired(true);
        return a.build();
    }

    static PendingIntent decision(Context ctx, String id, String decision) {
        Intent i = new Intent(ctx, DecisionReceiver.class)
                .setData(Uri.fromParts("sshd", id, decision)) // distinct PendingIntent per button
                .putExtra("id", id)
                .putExtra("decision", decision);
        return PendingIntent.getBroadcast(ctx, 0, i, PendingIntent.FLAG_IMMUTABLE);
    }

    /** Drops answers android-sshd never picked up (e.g. a deny after it timed out). */
    static void pruneAnswers(Context ctx) {
        File[] files = ctx.getFilesDir().listFiles();
        if (files == null) return;
        long cutoff = System.currentTimeMillis() - 3600_000L;
        for (File f : files) if (f.lastModified() < cutoff) f.delete();
    }
}
