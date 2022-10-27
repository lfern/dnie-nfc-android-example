package com.example.dnieexample;

import static android.view.View.GONE;
import static android.view.View.VISIBLE;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;

import com.gemalto.jp2.JP2Decoder;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import es.gob.jmulticard.BcCryptoHelper;
import es.gob.jmulticard.CryptoHelper;
import es.gob.jmulticard.apdu.connection.ApduConnectionException;
import es.gob.jmulticard.apdu.connection.cwa14890.Cwa14890OneV1Connection;
import es.gob.jmulticard.card.InvalidCardException;
import es.gob.jmulticard.card.dnie.BurnedDnieCardException;
import es.gob.jmulticard.card.dnie.Dnie3;
import es.gob.jmulticard.card.dnie.Dnie3Cwa14890Constants;
import es.gob.jmulticard.card.dnie.DnieFactory;
import es.gob.jmulticard.card.icao.Mrz;
import es.gob.jmulticard.card.iso7816four.Iso7816FourCardException;
import es.gob.jmulticard.jse.provider.ProviderUtil;
import es.gob.jmulticard.android.nfc.AndroidNfcConnection;

public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private ImageView _photo;
    private TextView _text;
    String can = "";
    private View _buttonCan;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        EnableReaderMode(this);

        setContentView(R.layout.activity_main);
        _text = findViewById(R.id.textView);
        _photo = findViewById(R.id.imageView);
        _buttonCan = findViewById(R.id.setCan);

        _buttonCan.setOnClickListener(v -> {
            LayoutInflater factory = LayoutInflater.from(MainActivity.this);
            final View canEntryView = factory.inflate(R.layout.sample_can, null);
            final AlertDialog ad = new AlertDialog.Builder(MainActivity.this).create();
            ad.setCancelable(true);
            ad.setIcon(R.drawable.alert_dialog_icon);
            ad.setView(canEntryView);
            ad.setButton(AlertDialog.BUTTON_POSITIVE, "Aceptar", (dialog, which) -> {
                EditText text = (EditText) ad.findViewById(R.id.can_edit);
                can = text.getText().toString();
            });
            ad.setButton(AlertDialog.BUTTON_NEGATIVE, "Cancelar", (dialog, which) -> ad.dismiss());
            ad.show();
        });

    }

     private void updateInfo(final String status, final Bitmap photo){
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                _text.setText(status);

                if(photo!=null){
                    _photo.setVisibility(VISIBLE);
                    _photo.setImageDrawable(new BitmapDrawable(getResources(), photo));
                    _photo.invalidate();
                }
                else _photo.setVisibility(GONE);
            }
        });
    }

    public static NfcAdapter EnableReaderMode (Activity activity)
    {
        NfcAdapter nfcAdapter = NfcAdapter.getDefaultAdapter(activity);
        Bundle options = new Bundle();
        options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 1000);
        nfcAdapter.enableReaderMode(activity,
                (NfcAdapter.ReaderCallback) activity,
                NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK 	|
                        NfcAdapter.FLAG_READER_NFC_A 	|
                        NfcAdapter.FLAG_READER_NFC_B,
                options);

        return nfcAdapter;
    }

    @Override
    public void onTagDiscovered(Tag tag) {
        updateInfo("Leyendo DNIe...", null);
        final CryptoHelper cryptoHelper = new BcCryptoHelper();
        final Dnie3 dnie;
        try {
            dnie = (Dnie3) DnieFactory.getDnie(
                    new AndroidNfcConnection(tag),
                    //ProviderUtil.getDefaultConnection(),
                    null,
                    cryptoHelper,
                    new TestingDnieCallbackHandler(new String(can), (String)null), // No usamos el PIN
                    false // No cargamos certificados ni nada
            );

            // TODO: Este certificado hay que verificarlo contra su CA raíz (que deberíamos tener preconfigurada)
            final X509Certificate iccCert = dnie.getIccCert();
            // Este aleatorio hay que generarlo en servidor, nunca en cliente
            final byte[] randomIfd = cryptoHelper.generateRandomBytes(8);
            // Con este aleatorio abrimos el canal CWA-14890:
            updateInfo("Abriendo canal seguro ...", null);
            final Dnie3Cwa14890Constants constants = DnieFactory.getDnie3UsrCwa14890Constants(dnie.getIdesp());
            dnie.verifyIfdCertificateChain(constants);
            final byte[] sigMinCiphered =
                    Cwa14890OneV1Connection.internalAuthGetInternalAuthenticateMessage(
                            dnie,
                            constants,
                            randomIfd
                    );
            // Esta comprobación se realiza en servidor
            updateInfo("Validando canal seguro ...", null);
            Cwa14890OneV1Connection.internalAuthValidateInternalAuthenticateMessage(
                    constants.getChrCCvIfd(), // CHR de la clave publica del cert de terminal.
                    sigMinCiphered, // Mensaje de autenticación generado en tarjeta.
                    randomIfd, // Aleatorio del desafío del terminal.
                    constants.getIfdPrivateKey(), // Clave privada del certificado de terminal.
                    constants.getIfdKeyLength(), // Longitud de las claves del cert de componente.
                    constants, // Constantes privadas de apertura de canal CWA.
                    constants, // Constantes públicas de apertura de canal CWA.
                    (RSAPublicKey) iccCert.getPublicKey(), // Clave pública del certificado de componente.
                    cryptoHelper // Utilidad de funciones criptográficas.
            );


            updateInfo("Obteniendo datos ...", null);
            final Mrz mrzData = dnie.getDg1();
            updateInfo("Obteniendo foto ...", null);
            final byte[] photoBytes = dnie.getDg2().getSubjectPhotoAsJpeg2k();
            Bitmap photo = new JP2Decoder(photoBytes).decode();
            updateInfo(mrzData.getName() + " " + mrzData.getSurname(), photo);
        } catch (InvalidCardException e) {
            updateInfo(e.getMessage(), null);
            e.printStackTrace();
        } catch (BurnedDnieCardException e) {
            updateInfo(e.getMessage(), null);
            e.printStackTrace();
        } catch (ApduConnectionException e) {
            updateInfo(e.getMessage(), null);
            e.printStackTrace();
        } catch (IOException e) {
            updateInfo(e.getMessage(), null);
            e.printStackTrace();
        } catch (Iso7816FourCardException e) {
            updateInfo(e.getMessage(), null);
            e.printStackTrace();
        }
    }
}