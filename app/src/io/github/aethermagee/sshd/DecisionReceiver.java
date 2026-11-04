package io.github.aethermagee.sshd;

import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/** Records a button press where android-sshd polls for it: files/<id>. */
public class DecisionReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context ctx, Intent in) {
        String id = in.getStringExtra("id");
        String decision = in.getStringExtra("decision");
        if (!PromptReceiver.validId(id) || decision == null) return;
        ctx.getSystemService(NotificationManager.class).cancel(id, 0);

        File f = new File(ctx.getFilesDir(), id);
        if (f.exists()) return; // first answer wins (e.g. Allow, then the dismissal's deny)
        File tmp = new File(ctx.getFilesDir(), id + ".tmp");
        try (FileOutputStream out = new FileOutputStream(tmp)) {
            out.write(decision.getBytes());
        } catch (IOException e) {
            return;
        }
        tmp.renameTo(f);
    }
}
