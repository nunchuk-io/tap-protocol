package com.example.tap_protocol_nativesdk;

import android.app.PendingIntent;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.TagLostException;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import com.example.tap_protocol_nativesdk.databinding.ActivityMainBinding;

import java.io.IOException;


public class MainActivity extends AppCompatActivity {

    private static final String TAG = "nothing";
    public NfcAdapter nfcAdapter;
    PendingIntent pendingIntent;

    @RequiresApi(api = Build.VERSION_CODES.ICE_CREAM_SANDWICH)
    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        resolveIntent(intent);
    }


    @RequiresApi(api = Build.VERSION_CODES.ICE_CREAM_SANDWICH)
    private void resolveIntent(Intent intent) {
        String action = intent.getAction();
//        byte[] id = intent.getByteArrayExtra(NfcAdapter.EXTRA_ID);
        Tag tag = (Tag) intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
//        String newTagID = new String(tag.getId());
        Toast.makeText(this, "Tag is: " + tag.toString(), Toast.LENGTH_SHORT).show();
        TextView tv = binding.sampleText;
        TextView tv2 = binding.sampleText2;

        try {
            IsoDep isoDep = IsoDep.get(tag);
//            isoDep.setTimeout(2500);
            IsoDepHolder.init(isoDep);

            Log.d("NFC", "tag connected");
            if (IsoDepHolder.isConnected()) {
                addTapSigner();
                String status = tapSignerStatus();
                tv.setText(status);

                String certs = tapSignerCerts();
                tv2.setText(certs);
            } else {

            }

        } catch (TagLostException e) {
            Log.d("NFC", "tag lost " + e.getMessage());
            e.printStackTrace();
            return;
        } catch (IOException e) {
            Log.d("NFC", "tag error " + e.getMessage());
            e.printStackTrace();
            return;
        } catch (Exception e) {
            Log.d("NFC", "error " + e.getMessage());
        } finally {
            Log.d("NFC", "closing tag");
            try {
                IsoDepHolder.close();
            } catch (IOException e) {

            }
        }

    }

    // Used to load the 'tap_protocol_nativesdk' library on application startup.
    static {
        System.loadLibrary("tap_protocol_nativesdk");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onResume() {
        super.onResume();

        if (nfcAdapter != null) {
            if (!nfcAdapter.isEnabled())
                showWirelessSettings();
            nfcAdapter.enableForegroundDispatch(this, pendingIntent, null, null);
        }
    }

    private void showWirelessSettings() {
        Toast.makeText(this, "You need to enable NFC", Toast.LENGTH_SHORT).show();
        Intent intent = new Intent(Settings.ACTION_WIRELESS_SETTINGS);
        startActivity(intent);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.d(TAG, "onCreate");
        nfcAdapter = NfcAdapter.getDefaultAdapter(this);

        if (nfcAdapter == null) {
            Toast.makeText(this, "No NFC", Toast.LENGTH_SHORT).show();
            finish();
            return;
        }

        pendingIntent = PendingIntent.getActivity(this, 0,
                new Intent(this, this.getClass())
                        .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);


        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Example of a call to a native method
        TextView tv = binding.sampleText;

        binding.button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                TextView tv = binding.sampleText2;
                String certs = tapSignerCerts();
                tv.setText(certs);
            }
        });
        tv.setText(stringFromJNI());
    }

    /**
     * A native method that is implemented by the 'tap_protocol_nativesdk' native library,
     * which is packaged with this application.
     */
    public native String stringFromJNI();

    public native void addTapSigner();

    public native String tapSignerStatus();

    public native String tapSignerCerts();
}