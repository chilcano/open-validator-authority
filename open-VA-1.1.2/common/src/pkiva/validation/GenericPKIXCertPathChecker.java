/*
* Copyright (C) 2006 netfocus S.L.
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU General Public License as published by the Free Software
* Foundation; either version 2 of the License, or (at your option) any later
* version.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along with
* this program; if not, write to the Free Software Foundation, Inc., 59 Temple
* Place, Suite 330, Boston, MA 02111-1307 USA
*/
package pkiva.validation;

import java.util.*;
//import java.security.*;
import java.security.cert.*;
import javax.resource.cci.*;

import pkiva.validation.ocsp.connectors.*;
import pkiva.services.*;

/**
 * Generic class extended from <code>PKIXCertPathChecker</code>
 */
public abstract class GenericPKIXCertPathChecker extends PKIXCertPathChecker {
    /**
     * Default Constructor.
     */
    protected GenericPKIXCertPathChecker() {  }
    
    /**
     * Performs the revocation status check on the certificate using
     * its internal state.
     *
     * @param cert the Certificate
     * @param unresolvedCritExts a Collection of the unresolved critical
     * extensions
     * @exception CertPathValidatorException Exception thrown if
     * certificate does not verify
     */
    public void check(Certificate cert, Collection unresolvedCritExts) throws CertPathValidatorException 
    {
      checkWithResponse ( cert, unresolvedCritExts );
    }

    public abstract ValidationObject checkWithResponse( Certificate cert, Collection unresolvedCritExts) throws CertPathValidatorException;
}
